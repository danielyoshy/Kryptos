#!/usr/bin/env python3
"""cenc - passphrase-based authenticated file encryption with a custom container.

Container layout (``.enc``)::

    offset   size  field
    ------   ----  -----------------------------------------------------------
    0        4     magic       b"CENC"
    4        1     version     0x01 = Argon2id            + AES-256-GCM
                               0x02 = PBKDF2-HMAC-SHA256  + AES-256-GCM
    5        16    salt        random per file (KDF salt)
    21       12    nonce       random per file (GCM IV)
    33       n     ciphertext  same length as the plaintext
    33+n     16    tag         GCM authentication tag

The full 33-byte header is bound to the ciphertext as GCM *associated data*,
so tampering with the magic, version, salt or nonce is detected exactly like
tampering with the ciphertext or tag.

Files are processed in chunks, so arbitrarily large files (up to the GCM
single-message limit of ~64 GiB) use constant memory. Output is written to a
temporary file in the destination directory and only moved into place after
the operation succeeds; during decryption this means unauthenticated
plaintext is never left behind if the tag check fails.

After encrypting, the original file is overwritten with random bytes and
deleted (unless ``--keep`` is given). This happens only after the new
container has been re-read and authenticated, so a failed write can never
cost you the original.

Usage::

    python cenc.py encrypt secret.pdf            # -> secret.pdf.enc, secret.pdf deleted
    python cenc.py encrypt secret.pdf --keep     # -> secret.pdf.enc, secret.pdf kept
    python cenc.py decrypt secret.pdf.enc        # -> secret.pdf
    python cenc.py verify  secret.pdf.enc        # check password + integrity
    python cenc.py info    secret.pdf.enc        # show header (no password)

Requires: ``pip install "cryptography>=44"`` (Argon2id support).
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import secrets
import stat
import struct
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, Optional, Union

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:  # Argon2id was added in cryptography 44.0
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError:  # pragma: no cover - depends on installed version
    Argon2id = None  # type: ignore[assignment,misc]

PathLike = Union[str, "os.PathLike[str]"]
# progress(phase, bytes_done, bytes_total); may raise OperationCancelled to abort.
ProgressCallback = Callable[[str, int, int], None]

# --------------------------------------------------------------------------- #
# Format constants
# --------------------------------------------------------------------------- #

MAGIC = b"CENC"
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32  # AES-256

# magic(4) | version(1) | salt(16) | nonce(12)  -> 33 bytes
HEADER_STRUCT = struct.Struct(f">{len(MAGIC)}sB{SALT_LEN}s{NONCE_LEN}s")
HEADER_LEN = HEADER_STRUCT.size

CHUNK_SIZE = 1 << 20  # 1 MiB streaming chunks

# NIST SP 800-38D: max plaintext per (key, nonce) is 2^39 - 256 bits.
GCM_MAX_PLAINTEXT = (2**39 - 256) // 8

ENC_SUFFIX = ".enc"

# KDF parameters (fixed per format version so decryption is deterministic).
ARGON2ID_TIME_COST = 3
ARGON2ID_MEMORY_KIB = 64 * 1024  # 64 MiB
ARGON2ID_LANES = 4
PBKDF2_ITERATIONS = 600_000


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class CencError(Exception):
    """Base class for all errors raised by this utility."""


class InvalidFormatError(CencError):
    """The input is not a valid / supported CENC container."""


class AuthenticationError(CencError):
    """GCM tag verification failed (wrong password or modified data)."""


class OutputExistsError(CencError):
    """Refusing to overwrite an existing output file."""


class SourceRemovalError(CencError):
    """Encryption succeeded, but the original file could not be removed."""


class OperationCancelled(CencError):
    """The user cancelled the operation (raised from a progress callback)."""


# --------------------------------------------------------------------------- #
# Key derivation / cipher suites
# --------------------------------------------------------------------------- #

def _derive_argon2id(password: bytes, salt: bytes) -> bytes:
    if Argon2id is None:
        raise CencError("Argon2id requires cryptography >= 44.0 (pip install -U cryptography)")
    try:
        kdf = Argon2id(
            salt=salt,
            length=KEY_LEN,
            iterations=ARGON2ID_TIME_COST,
            lanes=ARGON2ID_LANES,
            memory_cost=ARGON2ID_MEMORY_KIB,
        )
    except UnsupportedAlgorithm as exc:
        raise CencError("Argon2id is not supported by this cryptography/OpenSSL build") from exc
    return kdf.derive(password)


def _derive_pbkdf2(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password)


@dataclass(frozen=True)
class CipherSuite:
    """Everything a format version pins down: the KDF and its parameters."""

    version: int
    name: str
    derive_key: Callable[[bytes, bytes], bytes]


VERSION_ARGON2ID = 0x01
VERSION_PBKDF2 = 0x02

SUITES: dict[int, CipherSuite] = {
    s.version: s
    for s in (
        CipherSuite(
            VERSION_ARGON2ID,
            f"Argon2id (t={ARGON2ID_TIME_COST}, m={ARGON2ID_MEMORY_KIB // 1024} MiB, "
            f"p={ARGON2ID_LANES}) + AES-256-GCM",
            _derive_argon2id,
        ),
        CipherSuite(
            VERSION_PBKDF2,
            f"PBKDF2-HMAC-SHA256 ({PBKDF2_ITERATIONS:,} iterations) + AES-256-GCM",
            _derive_pbkdf2,
        ),
    )
}

KDF_CHOICES = {"argon2id": VERSION_ARGON2ID, "pbkdf2": VERSION_PBKDF2}


def argon2_available() -> bool:
    """Return True if this environment can perform Argon2id."""
    if Argon2id is None:
        return False
    try:
        Argon2id(salt=bytes(SALT_LEN), length=KEY_LEN, iterations=1, lanes=1, memory_cost=8)
    except UnsupportedAlgorithm:
        return False
    return True


def default_version() -> int:
    """Prefer Argon2id; fall back to PBKDF2 where Argon2id is unavailable."""
    return VERSION_ARGON2ID if argon2_available() else VERSION_PBKDF2


def _encode_password(password: str) -> bytes:
    """NFC-normalise so the same passphrase yields the same key on every OS."""
    if not password:
        raise CencError("password must not be empty")
    return unicodedata.normalize("NFC", password).encode("utf-8")


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Header:
    version: int
    salt: bytes
    nonce: bytes

    @property
    def suite(self) -> CipherSuite:
        return SUITES[self.version]

    def pack(self) -> bytes:
        return HEADER_STRUCT.pack(MAGIC, self.version, self.salt, self.nonce)

    @classmethod
    def new(cls, version: int) -> "Header":
        if version not in SUITES:
            raise CencError(f"unknown format version 0x{version:02x}")
        return cls(version, secrets.token_bytes(SALT_LEN), secrets.token_bytes(NONCE_LEN))

    @classmethod
    def unpack(cls, raw: bytes) -> "Header":
        if raw[: len(MAGIC)] != MAGIC:
            raise InvalidFormatError("not a CENC container (magic bytes missing or incorrect)")
        if len(raw) < HEADER_LEN:
            raise InvalidFormatError("file is truncated (incomplete header)")
        _, version, salt, nonce = HEADER_STRUCT.unpack(raw[:HEADER_LEN])
        if version not in SUITES:
            raise InvalidFormatError(f"unsupported format version 0x{version:02x}")
        return cls(version, salt, nonce)


@dataclass(frozen=True)
class ContainerInfo:
    header: Header
    ciphertext_len: int
    tag: bytes


def _read_container(fin: BinaryIO) -> ContainerInfo:
    """Parse and validate the container layout.

    Leaves ``fin`` positioned at the first ciphertext byte.
    """
    size = os.fstat(fin.fileno()).st_size
    fin.seek(0)
    header = Header.unpack(fin.read(HEADER_LEN))
    if size < HEADER_LEN + TAG_LEN:
        raise InvalidFormatError("file is truncated (authentication tag missing)")
    ct_len = size - HEADER_LEN - TAG_LEN
    fin.seek(HEADER_LEN + ct_len)
    tag = fin.read(TAG_LEN)
    fin.seek(HEADER_LEN)
    return ContainerInfo(header, ct_len, tag)


# --------------------------------------------------------------------------- #
# Streaming crypto core
# --------------------------------------------------------------------------- #

def _report(progress: Optional[ProgressCallback], phase: str, done: int, total: int) -> None:
    if progress is not None:
        progress(phase, done, total)


def _encrypt_stream(fin: BinaryIO, fout: BinaryIO, key: bytes, header: Header,
                    chunk_size: int, total: int = 0,
                    progress: Optional[ProgressCallback] = None) -> None:
    header_bytes = header.pack()
    encryptor = Cipher(algorithms.AES(key), modes.GCM(header.nonce)).encryptor()
    encryptor.authenticate_additional_data(header_bytes)

    fout.write(header_bytes)
    done = 0
    _report(progress, "Encrypting", done, total)
    while chunk := fin.read(chunk_size):
        fout.write(encryptor.update(chunk))
        done += len(chunk)
        _report(progress, "Encrypting", done, total)
    fout.write(encryptor.finalize())
    fout.write(encryptor.tag)


def _decrypt_stream(fin: BinaryIO, sink: Callable[[bytes], object], password: bytes,
                    chunk_size: int, phase: str = "Decrypting",
                    progress: Optional[ProgressCallback] = None) -> Header:
    info = _read_container(fin)
    _report(progress, "Deriving key", 0, 1)
    key = info.header.suite.derive_key(password, info.header.salt)
    _decrypt_payload(fin, info, key, sink, chunk_size, phase, progress)
    return info.header


def _decrypt_payload(fin: BinaryIO, info: ContainerInfo, key: bytes,
                     sink: Callable[[bytes], object], chunk_size: int,
                     phase: str = "Decrypting",
                     progress: Optional[ProgressCallback] = None) -> None:
    """Stream-decrypt the ciphertext (``fin`` positioned after the header)."""
    header = info.header
    decryptor = Cipher(algorithms.AES(key), modes.GCM(header.nonce, info.tag)).decryptor()
    decryptor.authenticate_additional_data(header.pack())

    total = info.ciphertext_len
    remaining = total
    _report(progress, phase, 0, total)
    while remaining:
        chunk = fin.read(min(chunk_size, remaining))
        if not chunk:
            raise InvalidFormatError("file changed size while being read")
        remaining -= len(chunk)
        sink(decryptor.update(chunk))
        _report(progress, phase, total - remaining, total)

    try:
        tail = decryptor.finalize()  # verifies the tag
    except InvalidTag:
        raise AuthenticationError(
            "authentication failed: the password is incorrect, or the file has been "
            "corrupted or tampered with"
        ) from None
    sink(tail)


def _verify_container(path: Path, key: bytes, chunk_size: int,
                      progress: Optional[ProgressCallback] = None) -> None:
    """Re-read a freshly written container and check that it authenticates."""
    with open(path, "rb") as fin:
        info = _read_container(fin)
        _decrypt_payload(fin, info, key, lambda _data: None, chunk_size, "Verifying", progress)


def _wipe_and_delete(path: Path, chunk_size: int = CHUNK_SIZE) -> None:
    """Overwrite a file's contents with random bytes, then delete it.

    This is best-effort only: SSD wear-levelling, journaling/copy-on-write
    file systems, backups and cloud sync (e.g. OneDrive version history) can
    all keep older copies of the data that this cannot reach.
    """
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)  # clear read-only (Windows)
    remaining = path.stat().st_size
    with open(path, "r+b", buffering=0) as fh:
        while remaining:
            n = min(chunk_size, remaining)
            fh.write(os.urandom(n))
            remaining -= n
        os.fsync(fh.fileno())
    path.unlink()


# --------------------------------------------------------------------------- #
# Safe output handling
# --------------------------------------------------------------------------- #

@contextlib.contextmanager
def _atomic_output(dst: Path, overwrite: bool) -> Iterator[BinaryIO]:
    """Write to a temp file next to ``dst`` and move it into place on success.

    On any exception the temp file is removed, so a failed decryption never
    leaves (unauthenticated) partial plaintext on disk.
    """
    if dst.exists() and not overwrite:
        raise OutputExistsError(f"output file already exists: {dst} (use --force to overwrite)")

    fd, tmp_name = tempfile.mkstemp(dir=dst.parent, prefix=f".{dst.name}.", suffix=".part")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            yield fh
            fh.flush()
            os.fsync(fh.fileno())
        if dst.exists() and not overwrite:
            raise OutputExistsError(f"output file appeared while writing: {dst}")
        os.replace(tmp, dst)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def encrypt_file(src: PathLike, dst: PathLike, password: str, *,
                 version: Optional[int] = None, overwrite: bool = False,
                 remove_source: bool = False, chunk_size: int = CHUNK_SIZE,
                 progress: Optional[ProgressCallback] = None) -> Path:
    """Encrypt ``src`` into a CENC container at ``dst``.

    With ``remove_source=True`` the original is wiped and deleted, but only
    after the written container has been re-read and successfully
    authenticated, so the original is never lost to a bad write.

    ``progress(phase, done, total)`` is called as work proceeds; it may raise
    :class:`OperationCancelled` to abort (the original is then left intact).
    """
    src, dst = Path(src), Path(dst)
    pw = _encode_password(password)
    header = Header.new(default_version() if version is None else version)

    size = src.stat().st_size
    if size > GCM_MAX_PLAINTEXT:
        raise CencError("file too large for a single AES-GCM message (~64 GiB limit)")

    _report(progress, "Deriving key", 0, 1)
    key = header.suite.derive_key(pw, header.salt)
    with open(src, "rb") as fin, _atomic_output(dst, overwrite) as fout:
        _encrypt_stream(fin, fout, key, header, chunk_size, size, progress)

    if remove_source:
        _verify_container(dst, key, chunk_size, progress)  # raises -> original is kept
        _report(progress, "Deleting original", 0, 1)
        try:
            _wipe_and_delete(src, chunk_size)
        except OSError as exc:
            raise SourceRemovalError(
                f"encrypted to '{dst}', but could not delete the original '{src}': {exc}"
            ) from exc
    return dst


def encrypt_bytes(data: bytes, dst: PathLike, password: str, *,
                  version: Optional[int] = None, overwrite: bool = False,
                  chunk_size: int = CHUNK_SIZE,
                  progress: Optional[ProgressCallback] = None) -> Path:
    """Encrypt ``data`` directly from memory into a CENC container at ``dst``.

    Plaintext is never written to disk; the resulting container is re-read and
    verified before returning.
    """
    dst_path = Path(dst)
    pw = _encode_password(password)
    header = Header.new(default_version() if version is None else version)

    size = len(data)
    if size > GCM_MAX_PLAINTEXT:
        raise CencError("data too large for a single AES-GCM message (~64 GiB limit)")

    _report(progress, "Deriving key", 0, 1)
    key = header.suite.derive_key(pw, header.salt)
    with _atomic_output(dst_path, overwrite) as fout:
        _encrypt_stream(io.BytesIO(data), fout, key, header, chunk_size, size, progress)
    _verify_container(dst_path, key, chunk_size, progress)
    return dst_path


def decrypt_file(src: PathLike, dst: PathLike, password: str, *,
                 overwrite: bool = False, remove_source: bool = False,
                 chunk_size: int = CHUNK_SIZE,
                 progress: Optional[ProgressCallback] = None) -> Path:
    """Authenticate and decrypt the CENC container ``src`` into ``dst``.

    With ``remove_source=True`` the encrypted ``src`` container is wiped and
    deleted after ``dst`` has been authenticated and moved into place.
    """
    src, dst = Path(src), Path(dst)
    pw = _encode_password(password)
    with open(src, "rb") as fin:
        _read_container(fin)  # validate format before creating any output
        with _atomic_output(dst, overwrite) as fout:
            _decrypt_stream(fin, fout.write, pw, chunk_size, "Decrypting", progress)
    if remove_source and src.resolve() != dst.resolve():
        _report(progress, "Deleting encrypted file", 0, 1)
        try:
            _wipe_and_delete(src, chunk_size)
        except OSError as exc:
            raise SourceRemovalError(
                f"decrypted to '{dst}', but could not delete the encrypted file '{src}': {exc}"
            ) from exc
    return dst


def verify_file(src: PathLike, password: str, *, chunk_size: int = CHUNK_SIZE,
                progress: Optional[ProgressCallback] = None) -> Header:
    """Check password and integrity of ``src`` without writing any plaintext."""
    pw = _encode_password(password)
    with open(src, "rb") as fin:
        return _decrypt_stream(fin, lambda _data: None, pw, chunk_size, "Verifying", progress)


def read_container_info(src: PathLike) -> ContainerInfo:
    """Parse the container header (no password needed)."""
    with open(src, "rb") as fin:
        return _read_container(fin)


def is_cenc_file(src: PathLike) -> bool:
    """Return True if ``src`` is an existing file with a valid CENC container header + tag."""
    try:
        p = Path(src)
        if not p.is_file():
            return False
        read_container_info(p)
        return True
    except (CencError, OSError):
        return False


def count_enc_suffixes(src: PathLike) -> int:
    """Return the number of trailing ``.enc`` suffixes in ``src``'s file name."""
    name = Path(src).name
    count = 0
    while name.lower().endswith(ENC_SUFFIX) and len(name) > len(ENC_SUFFIX):
        name = name[: -len(ENC_SUFFIX)]
        count += 1
    return count


def strip_enc_suffixes(src: PathLike, max_strip: Optional[int] = None) -> Path:
    """Strip up to ``max_strip`` (or all if ``None``) trailing ``.enc`` suffixes from ``src``."""
    p = Path(src)
    name = p.name
    stripped = 0
    while name.lower().endswith(ENC_SUFFIX) and len(name) > len(ENC_SUFFIX):
        if max_strip is not None and stripped >= max_strip:
            break
        name = name[: -len(ENC_SUFFIX)]
        stripped += 1
    if stripped == 0:
        return p.with_name(p.name + ".dec")
    return p.with_name(name)


def encrypt_file_layers(src: PathLike, dst: PathLike, password: str, *,
                        layers: int = 1, version: Optional[int] = None,
                        overwrite: bool = False, remove_source: bool = False,
                        chunk_size: int = CHUNK_SIZE,
                        progress: Optional[ProgressCallback] = None) -> Path:
    """Encrypt ``src`` into ``dst`` applying ``layers`` nested CENC encryption layers.

    Each layer uses its own fresh random 16-byte salt, fresh random 12-byte nonce,
    derived key, and 16-byte GCM authentication tag. If ``layers == 1``, behaves
    identically to :func:`encrypt_file`.
    """
    if layers < 1:
        raise CencError("encryption layers must be at least 1")
    src_path, dst_path = Path(src), Path(dst)
    if layers == 1:
        return encrypt_file(src_path, dst_path, password, version=version,
                            overwrite=overwrite, remove_source=remove_source,
                            chunk_size=chunk_size, progress=progress)

    if src_path.resolve() == dst_path.resolve():
        raise CencError("input and output must be different files")
    if dst_path.exists() and not overwrite:
        raise OutputExistsError(f"output file already exists: {dst_path}")
    dst_path.parent.mkdir(parents=True, exist_ok=True)

    temps: list[Path] = []
    try:
        cur_src = src_path
        for i in range(1, layers + 1):
            is_last = i == layers
            cur_dst = (dst_path if is_last
                       else dst_path.parent / f".{dst_path.name}.layer{i}.{secrets.token_hex(4)}.part")
            if not is_last:
                temps.append(cur_dst)

            def layer_prog(phase: str, done: int, total: int, _idx: int = i) -> None:
                if progress is not None:
                    tag_phase = phase if phase in ("Deriving key", "Deleting original") else f"{phase} (layer {_idx}/{layers})"
                    progress(tag_phase, done, total)

            encrypt_file(
                cur_src, cur_dst, password, version=version,
                overwrite=overwrite if is_last else True,
                remove_source=False, chunk_size=chunk_size, progress=layer_prog,
            )
            cur_src = cur_dst

        if remove_source:
            _report(progress, "Deleting original", 0, 1)
            try:
                _wipe_and_delete(src_path, chunk_size)
            except OSError as exc:
                raise SourceRemovalError(
                    f"encrypted to '{dst_path}', but could not delete the original '{src_path}': {exc}"
                ) from exc
        return dst_path
    finally:
        for t in temps:
            if t.exists():
                with contextlib.suppress(OSError):
                    _wipe_and_delete(t, chunk_size)


def encrypt_bytes_layers(data: bytes, dst: PathLike, password: str, *,
                         layers: int = 1, version: Optional[int] = None,
                         overwrite: bool = False, chunk_size: int = CHUNK_SIZE,
                         progress: Optional[ProgressCallback] = None) -> Path:
    """Encrypt ``data`` from memory into ``dst`` with ``layers`` nested CENC layers."""
    if layers < 1:
        raise CencError("encryption layers must be at least 1")
    dst_path = Path(dst)
    if layers == 1:
        return encrypt_bytes(data, dst_path, password, version=version,
                             overwrite=overwrite, chunk_size=chunk_size, progress=progress)
    if dst_path.exists() and not overwrite:
        raise OutputExistsError(f"output file already exists: {dst_path}")
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    tmp1 = dst_path.parent / f".{dst_path.name}.layer1.{secrets.token_hex(4)}.part"
    try:
        encrypt_bytes(data, tmp1, password, version=version, overwrite=True,
                      chunk_size=chunk_size, progress=progress)
        return encrypt_file_layers(tmp1, dst_path, password, layers=layers - 1,
                                   version=version, overwrite=overwrite,
                                   remove_source=True, chunk_size=chunk_size,
                                   progress=progress)
    finally:
        if tmp1.exists():
            with contextlib.suppress(OSError):
                _wipe_and_delete(tmp1, chunk_size)


def decrypt_file_layers(src: PathLike, dst: PathLike, password: str, *,
                        unwrap_all: bool = False, overwrite: bool = False,
                        remove_source: bool = True, chunk_size: int = CHUNK_SIZE,
                        progress: Optional[ProgressCallback] = None) -> tuple[Path, int, bool]:
    """Decrypt 1 layer (or all matching layers if ``unwrap_all=True``) from ``src`` into ``dst``.

    Returns ``(output_path, layers_decrypted, still_encrypted)``.
    When ``unwrap_all=True``, keeps peeling nested CENC layers as long as they
    authenticate with ``password``; if an inner layer requires a different
    password, stops cleanly at that inner container and returns it with
    ``still_encrypted=True``.
    """
    src_path, dst_path = Path(src), Path(dst)
    if not unwrap_all:
        decrypt_file(src_path, dst_path, password, overwrite=overwrite,
                     remove_source=remove_source, chunk_size=chunk_size,
                     progress=progress)
        still_enc = is_cenc_file(dst_path)
        return dst_path, 1, still_enc

    # Multi-layer unwrap mode: peel Layer 1 first (raises AuthenticationError if password wrong).
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    cur_out = dst_path.parent / f".{dst_path.name}.unwrap1.{secrets.token_hex(4)}.part"
    temps: list[Path] = [cur_out]
    layers_done = 0
    try:
        decrypt_file(src_path, cur_out, password, overwrite=True,
                     chunk_size=chunk_size, progress=progress)
        layers_done = 1
        while is_cenc_file(cur_out) and layers_done < 32:
            nxt_out = dst_path.parent / f".{dst_path.name}.unwrap{layers_done + 1}.{secrets.token_hex(4)}.part"
            temps.append(nxt_out)
            try:
                decrypt_file(cur_out, nxt_out, password, overwrite=True,
                             chunk_size=chunk_size, progress=progress)
            except AuthenticationError:
                # Inner layer was encrypted with a different password; stop here!
                break
            layers_done += 1
            cur_out = nxt_out

        still_enc = is_cenc_file(cur_out)
        # If the user left the default single-step output name (which still ends in .enc)
        # and we unwrapped more than 1 layer, adjust the output filename to match how many
        # layers were actually peeled.
        final_dst = dst_path
        default_one = _default_decrypt_output(src_path)
        if dst_path == default_one and layers_done > 1:
            final_dst = strip_enc_suffixes(src_path, max_strip=layers_done)
            if still_enc and not final_dst.name.lower().endswith(ENC_SUFFIX):
                final_dst = final_dst.with_name(final_dst.name + ENC_SUFFIX)

        if final_dst.exists() and not overwrite and final_dst.resolve() != src_path.resolve():
            raise OutputExistsError(f"output file already exists: {final_dst}")
        os.replace(cur_out, final_dst)

        if remove_source and final_dst.resolve() != src_path.resolve():
            try:
                _wipe_and_delete(src_path, chunk_size)
            except OSError as exc:
                raise SourceRemovalError(
                    f"decrypted to '{final_dst}', but could not delete '{src_path}': {exc}"
                ) from exc
        return final_dst, layers_done, still_enc
    finally:
        for t in temps:
            if t.exists():
                with contextlib.suppress(OSError):
                    _wipe_and_delete(t, chunk_size)


# --------------------------------------------------------------------------- #
# Command-line interface
# --------------------------------------------------------------------------- #

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FORMAT = 3
EXIT_AUTH = 4
EXIT_SOURCE_NOT_REMOVED = 5
EXIT_INTERRUPTED = 130


def _prompt_password(confirm: bool) -> str:
    password = getpass("Password: ")
    if not password:
        raise CencError("password must not be empty")
    if confirm and getpass("Confirm password: ") != password:
        raise CencError("passwords do not match")
    return password


def _check_paths(src: Path, dst: Optional[Path], overwrite: bool) -> None:
    """Fail fast (before prompting for a password) on obvious path problems."""
    if not src.is_file():
        raise CencError(f"input file not found: {src}")
    if dst is None:
        return
    if src.resolve() == dst.resolve():
        raise CencError("input and output must be different files")
    if dst.exists() and not overwrite:
        raise OutputExistsError(f"output file already exists: {dst} (use --force to overwrite)")


def _default_decrypt_output(src: Path) -> Path:
    if src.suffix.lower() == ENC_SUFFIX and src.stem:
        return src.with_suffix("")
    return src.with_name(src.name + ".dec")


def _cmd_encrypt(args: argparse.Namespace) -> int:
    src: Path = args.input
    dst: Path = args.output or src.with_name(src.name + ENC_SUFFIX)
    _check_paths(src, dst, args.force)

    if args.kdf is None:
        version = default_version()
    else:
        version = KDF_CHOICES[args.kdf]
        if version == VERSION_ARGON2ID and not argon2_available():
            raise CencError("Argon2id is unavailable here; use --kdf pbkdf2 or upgrade cryptography")

    password = _prompt_password(confirm=True)
    encrypt_file(src, dst, password, version=version, overwrite=args.force,
                 remove_source=not args.keep)
    print(f"Encrypted '{src}' -> '{dst}' [{SUITES[version].name}]")
    if args.keep:
        print(f"Original kept: '{src}'")
    else:
        print(f"Original wiped and deleted: '{src}' (decrypt '{dst}' to restore it)")
    return EXIT_OK


def _cmd_decrypt(args: argparse.Namespace) -> int:
    src: Path = args.input
    dst: Path = args.output or _default_decrypt_output(src)
    _check_paths(src, dst, args.force)
    read_container_info(src)  # reject non-CENC files before asking for a password

    password = _prompt_password(confirm=False)
    decrypt_file(src, dst, password, overwrite=args.force)
    print(f"Decrypted '{src}' -> '{dst}'")
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    src: Path = args.input
    _check_paths(src, None, False)
    read_container_info(src)

    password = _prompt_password(confirm=False)
    header = verify_file(src, password)
    print(f"OK: '{src}' is authentic and the password is correct [{header.suite.name}]")
    return EXIT_OK


def _cmd_info(args: argparse.Namespace) -> int:
    src: Path = args.input
    _check_paths(src, None, False)
    info = read_container_info(src)
    h = info.header
    print(f"File:       {src}")
    print(f"Format:     CENC v{h.version} - {h.suite.name}")
    print(f"Salt:       {h.salt.hex()}")
    print(f"Nonce:      {h.nonce.hex()}")
    print(f"Payload:    {info.ciphertext_len:,} bytes ciphertext + {TAG_LEN}-byte tag")
    print(f"Tag:        {info.tag.hex()}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cenc",
        description="Encrypt and decrypt files with AES-256-GCM using a passphrase "
                    "(Argon2id / PBKDF2 key derivation) and a verifiable .enc container.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("encrypt", help="encrypt a file (the original is deleted afterwards)")
    p.add_argument("input", type=Path, help="file to encrypt")
    p.add_argument("-o", "--output", type=Path, help="output path (default: INPUT.enc)")
    p.add_argument("-f", "--force", action="store_true", help="overwrite an existing output file")
    p.add_argument("-k", "--keep", action="store_true",
                   help="keep the original file instead of wiping and deleting it")
    p.add_argument("--kdf", choices=sorted(KDF_CHOICES),
                   help="key derivation function (default: argon2id if available, else pbkdf2)")
    p.set_defaults(func=_cmd_encrypt)

    p = sub.add_parser("decrypt", help="authenticate and decrypt a .enc file")
    p.add_argument("input", type=Path, help="file to decrypt")
    p.add_argument("-o", "--output", type=Path,
                   help="output path (default: INPUT without .enc, or INPUT.dec)")
    p.add_argument("-f", "--force", action="store_true", help="overwrite an existing output file")
    p.set_defaults(func=_cmd_decrypt)

    p = sub.add_parser("verify", help="check password and integrity without writing output")
    p.add_argument("input", type=Path, help="file to verify")
    p.set_defaults(func=_cmd_verify)

    p = sub.add_parser("info", help="show container header details (no password needed)")
    p.add_argument("input", type=Path, help="file to inspect")
    p.set_defaults(func=_cmd_info)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except InvalidFormatError as exc:
        print(f"cenc: invalid file format: {exc}", file=sys.stderr)
        return EXIT_FORMAT
    except AuthenticationError as exc:
        print(f"cenc: {exc}", file=sys.stderr)
        return EXIT_AUTH
    except SourceRemovalError as exc:
        print(f"cenc: warning: {exc}", file=sys.stderr)
        return EXIT_SOURCE_NOT_REMOVED
    except CencError as exc:
        print(f"cenc: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"cenc: I/O error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\ncenc: aborted", file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
