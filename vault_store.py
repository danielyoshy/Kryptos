#!/usr/bin/env python3
"""vault_store - managed file storage directory with encrypted/unencrypted filtering.

Provides a dedicated local folder (default: ``vault_storage/`` next to the app)
where files can be stored, listed, filtered by encryption status, imported,
exported, and securely removed.

Classification inspects the actual file header via :func:`cenc.read_container_info`,
not just the ``.enc`` extension:

* ``encrypted``: valid CENC container header + tag length (reports version & KDF).
* ``unencrypted``: any other file (even if named ``*.enc``).
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

import cenc

PathLike = Union[str, "os.PathLike[str]"]

DEFAULT_VAULT_DIR = Path(__file__).resolve().parent / "vault_storage"

FILTER_ALL = "all"
FILTER_ENCRYPTED = "encrypted"
FILTER_UNENCRYPTED = "unencrypted"
FILTERS = (FILTER_ALL, FILTER_ENCRYPTED, FILTER_UNENCRYPTED)


class VaultError(cenc.CencError):
    """Error raised during vault storage operations."""


@dataclass(frozen=True)
class VaultItem:
    name: str
    path: Path
    size: int
    modified: float
    encrypted: bool
    detail: str  # e.g. "CENC v1 (Argon2id)" or "Plain file (.pdf)"

    @property
    def status(self) -> str:
        return FILTER_ENCRYPTED if self.encrypted else FILTER_UNENCRYPTED

    @property
    def modified_iso(self) -> str:
        return datetime.fromtimestamp(self.modified).strftime("%Y-%m-%d %H:%M:%S")

    @property
    def layers(self) -> int:
        if not self.encrypted:
            return 0
        return max(1, cenc.count_enc_suffixes(self.name))


def ensure_vault_dir(vault_dir: Optional[PathLike] = None) -> Path:
    """Ensure the vault storage folder exists and return its Path."""
    target = Path(vault_dir) if vault_dir is not None else DEFAULT_VAULT_DIR
    target.mkdir(parents=True, exist_ok=True)
    return target


def inspect_item(path: PathLike) -> VaultItem:
    """Classify a single file on disk as encrypted (valid CENC) or unencrypted."""
    p = Path(path)
    st = p.stat()
    encrypted = False
    try:
        info = cenc.read_container_info(p)
        encrypted = True
        kdf_short = "Argon2id" if info.header.version == cenc.VERSION_ARGON2ID else "PBKDF2"
        n_layers = max(1, cenc.count_enc_suffixes(p.name))
        layer_tag = f" \u2022 {n_layers} layers" if n_layers > 1 else ""
        detail = f"CENC v{info.header.version} ({kdf_short} + AES-256-GCM){layer_tag}"
    except (cenc.CencError, OSError):
        ext = p.suffix.lower()
        if ext == cenc.ENC_SUFFIX:
            detail = "Unencrypted / non-CENC (.enc)"
        elif ext:
            detail = f"Plain file ({ext})"
        else:
            detail = "Plain file"
    return VaultItem(
        name=p.name,
        path=p,
        size=st.st_size,
        modified=st.st_mtime,
        encrypted=encrypted,
        detail=detail,
    )


def list_vault_items(vault_dir: Optional[PathLike] = None, *,
                     filter_mode: str = FILTER_ALL,
                     query: str = "") -> List[VaultItem]:
    """List files stored in ``vault_dir``, filtered by encryption status and name."""
    if filter_mode not in FILTERS:
        raise VaultError(f"unknown filter '{filter_mode}' (choose from {', '.join(FILTERS)})")
    root = ensure_vault_dir(vault_dir)
    needle = query.strip().lower()
    items: List[VaultItem] = []

    for entry in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if not entry.is_file():
            continue
        # Ignore temporary .part files created during atomic writes.
        if entry.name.startswith(".") and entry.name.endswith(".part"):
            continue
        try:
            item = inspect_item(entry)
        except OSError:
            continue
        if filter_mode == FILTER_ENCRYPTED and not item.encrypted:
            continue
        if filter_mode == FILTER_UNENCRYPTED and item.encrypted:
            continue
        if needle and needle not in item.name.lower():
            continue
        items.append(item)
    return items


def store_file(src: PathLike, vault_dir: Optional[PathLike] = None, *,
               move: bool = False, overwrite: bool = False) -> VaultItem:
    """Copy (or move) ``src`` into the vault storage directory."""
    src_path = Path(src)
    if not src_path.is_file():
        raise VaultError(f"source file not found: {src_path}")
    root = ensure_vault_dir(vault_dir)
    dst = root / src_path.name

    if src_path.resolve() == dst.resolve():
        return inspect_item(dst)
    if dst.exists() and not overwrite:
        raise cenc.OutputExistsError(f"'{dst.name}' is already stored in the vault")

    with cenc._atomic_output(dst, overwrite=overwrite) as fout, open(src_path, "rb") as fin:
        shutil.copyfileobj(fin, fout, length=cenc.CHUNK_SIZE)

    if move:
        try:
            cenc._wipe_and_delete(src_path)
        except OSError as exc:
            raise cenc.SourceRemovalError(
                f"stored '{dst.name}' in the vault, but could not remove original '{src_path}': {exc}"
            ) from exc

    return inspect_item(dst)


def export_file(name_or_path: PathLike, dst: PathLike,
                vault_dir: Optional[PathLike] = None, *,
                overwrite: bool = False) -> Path:
    """Copy a stored vault file out to ``dst``."""
    p = Path(name_or_path)
    if not p.is_absolute():
        p = ensure_vault_dir(vault_dir) / p
    if not p.is_file():
        raise VaultError(f"stored file not found: {p.name}")
    dst_path = Path(dst)
    if p.resolve() == dst_path.resolve():
        raise VaultError("destination must be outside the stored file itself")
    with cenc._atomic_output(dst_path, overwrite=overwrite) as fout, open(p, "rb") as fin:
        shutil.copyfileobj(fin, fout, length=cenc.CHUNK_SIZE)
    return dst_path


INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
RESERVED_WINDOWS_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def validate_filename(name: str, *, default_ext: str = ".txt") -> str:
    """Validate a plain file name (no directory components) and append a default extension if missing."""
    cleaned = name.strip().rstrip(". ")
    if not cleaned:
        raise VaultError("enter a file name")
    if "/" in cleaned or "\\" in cleaned or cleaned in (".", ".."):
        raise VaultError("file name must not contain folder slashes")
    if INVALID_FILENAME_CHARS.search(cleaned):
        raise VaultError('file name contains invalid characters (< > : " / \\ | ? *)')
    stem = Path(cleaned).stem if Path(cleaned).suffix else cleaned
    if stem.upper() in RESERVED_WINDOWS_NAMES:
        raise VaultError(f"'{cleaned}' is a reserved system name on Windows")
    if "." not in cleaned and default_ext:
        cleaned += default_ext
    return cleaned


def create_plain_file(dst: PathLike, content: Union[str, bytes], *,
                      overwrite: bool = False) -> Path:
    """Write ``content`` (UTF-8 str or raw bytes) atomically to ``dst``."""
    dst_path = Path(dst)
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    data = content.encode("utf-8") if isinstance(content, str) else content
    with cenc._atomic_output(dst_path, overwrite=overwrite) as fout:
        fout.write(data)
    return dst_path


def copy_plain_file(src: PathLike, dst: PathLike, *, overwrite: bool = False,
                    progress: Optional[cenc.ProgressCallback] = None) -> Path:
    """Stream-copy ``src`` to ``dst`` atomically in chunks without loading into RAM."""
    src_path = Path(src)
    if not src_path.is_file():
        raise VaultError(f"source file not found: {src_path}")
    dst_path = Path(dst)
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    if src_path.resolve() == dst_path.resolve():
        if progress is not None:
            size = dst_path.stat().st_size
            progress("Copying", size, size)
        return dst_path

    total = src_path.stat().st_size
    done = 0
    if progress is not None:
        progress("Copying", 0, total)
    with cenc._atomic_output(dst_path, overwrite=overwrite) as fout, open(src_path, "rb") as fin:
        while True:
            chunk = fin.read(cenc.CHUNK_SIZE)
            if not chunk:
                break
            fout.write(chunk)
            done += len(chunk)
            if progress is not None:
                progress("Copying", done, total)
    return dst_path


def remove_stored_file(name_or_path: PathLike, vault_dir: Optional[PathLike] = None, *,
                       secure: bool = True) -> None:
    """Remove a file from vault storage (securely wiping bytes first by default)."""
    root = ensure_vault_dir(vault_dir).resolve()
    p = Path(name_or_path)
    if not p.is_absolute():
        p = root / p
    resolved = p.resolve()
    if resolved.parent != root:
        raise VaultError("refusing to remove a file outside the vault storage directory")
    if not resolved.is_file():
        raise VaultError(f"stored file not found: {p.name}")
    if secure:
        cenc._wipe_and_delete(resolved)
    else:
        resolved.unlink()
