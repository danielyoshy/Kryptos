#!/usr/bin/env python3
"""integrity - file hash comparison and tamper-evident baselines.

Two complementary tools, built on the same streaming hash engine:

1. **Hash check**: compute a file's cryptographic hash and optionally compare it
   with an expected value (e.g. the checksum a download page publishes).

2. **Baseline**: record the hashes of a file or a whole folder in a small JSON
   file, then later re-check to see exactly which files were modified, deleted
   or added.

A plain baseline can be edited by anyone who can edit the files it describes.
To make unauthorised changes detectable *including to the baseline itself*,
protect it with a password (``--protect``): the baseline is then sealed with an
HMAC-SHA256 whose key is derived from the password with the same KDF
(Argon2id / PBKDF2) used by ``cenc.py``. Without the password nobody can
produce a baseline that verifies.

Usage::

    python integrity.py hash   report.pdf
    python integrity.py hash   setup.exe --expect sha256:9f86d0...
    python integrity.py baseline  C:\\data\\photos --protect
    python integrity.py check     photos.baseline.json

Only strong hash algorithms are offered (no MD5 / SHA-1).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, List, Optional, Tuple, Union

import cenc

PathLike = Union[str, "os.PathLike[str]"]

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# hashlib name -> display label
ALGORITHMS: Dict[str, str] = {
    "sha256": "SHA-256",
    "sha512": "SHA-512",
    "sha3_256": "SHA3-256",
    "blake2b": "BLAKE2b-512",
}
DEFAULT_ALGORITHM = "sha256"

CHUNK_SIZE = 1 << 20

BASELINE_FORMAT = "cenc-baseline"
BASELINE_VERSION = 1
BASELINE_SUFFIX = ".baseline.json"
MAC_CONTEXT = b"CENC-BASELINE-v1\n"

UNCHANGED, MODIFIED, MISSING, NEW, ERROR = "unchanged", "modified", "missing", "new", "error"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_MISMATCH = 6      # hash mismatch, or changes found against a baseline
EXIT_BASELINE_AUTH = 7  # baseline password wrong / baseline altered
EXIT_INTERRUPTED = 130


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class IntegrityError(cenc.CencError):
    """Base class for integrity-feature errors."""


class InvalidHashError(IntegrityError):
    """The expected hash text is not a valid hash for the chosen algorithm."""


class InvalidBaselineError(IntegrityError):
    """The baseline file is malformed or unsupported."""


class BaselineAuthError(IntegrityError):
    """Baseline authentication failed (wrong password, or the baseline was altered)."""


ProgressCallback = cenc.ProgressCallback


def _report(progress: Optional[ProgressCallback], phase: str, done: int, total: int) -> None:
    if progress is not None:
        progress(phase, done, total)


# --------------------------------------------------------------------------- #
# Hash engine
# --------------------------------------------------------------------------- #

def _check_algorithm(algorithm: str) -> str:
    if algorithm not in ALGORITHMS:
        raise IntegrityError(
            f"unsupported hash algorithm '{algorithm}' (choose from {', '.join(ALGORITHMS)})")
    return algorithm


def hex_length(algorithm: str) -> int:
    """Length in hex characters of a digest for ``algorithm``."""
    return hashlib.new(_check_algorithm(algorithm)).digest_size * 2


def _hash_path(path: Path, algorithm: str, chunk_size: int,
               on_bytes: Optional[Callable[[int], None]] = None) -> str:
    digest = hashlib.new(algorithm)
    with open(path, "rb") as fin:
        while chunk := fin.read(chunk_size):
            digest.update(chunk)
            if on_bytes is not None:
                on_bytes(len(chunk))
    return digest.hexdigest()


def hash_file(path: PathLike, algorithm: str = DEFAULT_ALGORITHM, *,
              chunk_size: int = CHUNK_SIZE,
              progress: Optional[ProgressCallback] = None) -> str:
    """Return the lowercase hex digest of ``path`` (streamed in chunks)."""
    _check_algorithm(algorithm)
    path = Path(path)
    total = path.stat().st_size
    done = 0
    _report(progress, "Hashing", 0, total)

    def on_bytes(n: int) -> None:
        nonlocal done
        done += n
        _report(progress, "Hashing", done, total)

    return _hash_path(path, algorithm, chunk_size, on_bytes)


def normalize_hash(text: str, algorithm: str) -> str:
    """Extract a clean lowercase hex digest from user-pasted text.

    Accepts the bare hash, ``sha256:<hash>``, ``<hash>  filename`` (sha256sum),
    ``SHA256 (file) = <hash>`` (BSD style) and hashes grouped with spaces or
    colons. Raises :class:`InvalidHashError` if no valid digest is found.
    """
    want = hex_length(algorithm)
    cleaned = text.strip()
    if not cleaned:
        raise InvalidHashError("no hash was entered")

    compact = re.sub(r"[\s:]", "", cleaned)
    if len(compact) == want and re.fullmatch(r"[0-9a-fA-F]+", compact):
        return compact.lower()

    pattern = r"(?<![0-9a-fA-F])[0-9a-fA-F]{%d}(?![0-9a-fA-F])" % want
    tokens = re.findall(pattern, cleaned)
    if len(set(t.lower() for t in tokens)) == 1:
        return tokens[0].lower()

    hint = ""
    if re.fullmatch(r"[0-9a-fA-F]+", compact):
        matches = [ALGORITHMS[a] for a in ALGORITHMS if hex_length(a) == len(compact)]
        if matches:
            hint = f" That is {len(compact)} characters long, which fits {' / '.join(matches)}."
        else:
            hint = f" That is {len(compact)} characters long."
    raise InvalidHashError(
        f"expected a {want}-character hexadecimal {ALGORITHMS[algorithm]} hash.{hint}")


@dataclass(frozen=True)
class HashComparison:
    algorithm: str
    actual: str
    expected: Optional[str]  # normalised; None if no comparison was requested

    @property
    def compared(self) -> bool:
        return self.expected is not None

    @property
    def match(self) -> bool:
        """True only if an expected hash was given and equals the actual one."""
        return self.expected is not None and hmac.compare_digest(self.actual, self.expected)


def compare_file_hash(path: PathLike, expected: Optional[str] = None,
                      algorithm: str = DEFAULT_ALGORITHM, *,
                      chunk_size: int = CHUNK_SIZE,
                      progress: Optional[ProgressCallback] = None) -> HashComparison:
    """Hash ``path`` and, if ``expected`` is given, compare against it.

    The expected value is validated *before* hashing so a typo fails instantly.
    """
    wanted = normalize_hash(expected, algorithm) if expected and expected.strip() else None
    actual = hash_file(path, algorithm, chunk_size=chunk_size, progress=progress)
    return HashComparison(algorithm, actual, wanted)


# --------------------------------------------------------------------------- #
# Baseline model
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class FileRecord:
    path: str   # POSIX-style, relative to the baseline root
    size: int
    hash: str


@dataclass(frozen=True)
class Auth:
    kdf: int
    salt: str  # hex
    mac: str = ""  # hex


@dataclass
class Baseline:
    algorithm: str
    created: str
    root: str
    is_dir: bool
    files: List[FileRecord]
    auth: Optional[Auth] = None

    @property
    def protected(self) -> bool:
        return self.auth is not None

    @property
    def total_size(self) -> int:
        return sum(f.size for f in self.files)

    def to_dict(self, include_mac: bool = True) -> dict:
        data: dict = {
            "format": BASELINE_FORMAT,
            "version": BASELINE_VERSION,
            "algorithm": self.algorithm,
            "created": self.created,
            "root": self.root,
            "is_dir": self.is_dir,
            "files": [{"path": f.path, "size": f.size, "hash": f.hash} for f in self.files],
        }
        if self.auth is not None:
            auth = {"kdf": self.auth.kdf, "salt": self.auth.salt}
            if include_mac:
                auth["mac"] = self.auth.mac
            data["auth"] = auth
        return data


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _compute_mac(baseline: Baseline, key: bytes) -> str:
    message = MAC_CONTEXT + _canonical(baseline.to_dict(include_mac=False))
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _derive_mac_key(password: str, kdf: int, salt: bytes,
                    progress: Optional[ProgressCallback]) -> bytes:
    suite = cenc.SUITES.get(kdf)
    if suite is None:
        raise InvalidBaselineError(f"unsupported key-derivation id {kdf} in baseline")
    pw = cenc._encode_password(password)
    _report(progress, "Deriving key", 0, 1)
    return suite.derive_key(pw, salt)


def _is_hex(text: object, length: int) -> bool:
    return (isinstance(text, str) and len(text) == length
            and re.fullmatch(r"[0-9a-fA-F]+", text) is not None)


def _safe_relative(path: str) -> bool:
    if not path or "\\" in path or path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        return False
    return all(part not in ("", ".", "..") for part in PurePosixPath(path).parts) \
        and PurePosixPath(path).as_posix() == path


def _parse_baseline(data: object) -> Baseline:
    def need(condition: bool, message: str) -> None:
        if not condition:
            raise InvalidBaselineError(message)

    need(isinstance(data, dict), "baseline is not a JSON object")
    assert isinstance(data, dict)
    need(data.get("format") == BASELINE_FORMAT, "not a CENC baseline file")
    need(data.get("version") == BASELINE_VERSION,
         f"unsupported baseline version {data.get('version')!r}")
    algorithm = data.get("algorithm")
    need(algorithm in ALGORITHMS, f"unsupported hash algorithm {algorithm!r} in baseline")
    need(isinstance(data.get("created"), str), "baseline is missing its creation time")
    need(isinstance(data.get("root"), str), "baseline is missing its root path")
    need(isinstance(data.get("is_dir"), bool), "baseline is missing 'is_dir'")
    raw_files = data.get("files")
    need(isinstance(raw_files, list) and raw_files, "baseline lists no files")

    want = hex_length(algorithm)
    files: List[FileRecord] = []
    seen = set()
    for entry in raw_files:
        need(isinstance(entry, dict), "baseline has a malformed file entry")
        path, size, digest = entry.get("path"), entry.get("size"), entry.get("hash")
        need(isinstance(path, str) and _safe_relative(path), f"unsafe or invalid path {path!r}")
        need(isinstance(size, int) and not isinstance(size, bool) and size >= 0,
             f"invalid size for {path!r}")
        need(_is_hex(digest, want), f"invalid hash for {path!r}")
        need(path not in seen, f"duplicate entry for {path!r}")
        seen.add(path)
        files.append(FileRecord(path, size, digest.lower()))
    need(data["is_dir"] or len(files) == 1, "a file baseline must contain exactly one file")

    auth: Optional[Auth] = None
    if "auth" in data and data["auth"] is not None:
        raw = data["auth"]
        need(isinstance(raw, dict), "baseline has a malformed 'auth' section")
        need(isinstance(raw.get("kdf"), int) and raw["kdf"] in cenc.SUITES,
             "baseline uses an unsupported key-derivation function")
        need(_is_hex(raw.get("salt"), cenc.SALT_LEN * 2), "baseline has an invalid salt")
        need(_is_hex(raw.get("mac"), 64), "baseline has an invalid authentication code")
        auth = Auth(raw["kdf"], raw["salt"].lower(), raw["mac"].lower())

    return Baseline(algorithm, data["created"], data["root"], data["is_dir"], files, auth)


def read_baseline(path: PathLike) -> Baseline:
    """Parse and validate a baseline file. Does **not** check its password/MAC."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InvalidBaselineError(f"not a valid baseline file ({exc})") from None
    return _parse_baseline(data)


def authenticate_baseline(baseline: Baseline, password: Optional[str], *,
                          progress: Optional[ProgressCallback] = None) -> None:
    """Verify a protected baseline's HMAC; no-op for unprotected baselines."""
    if baseline.auth is None:
        return
    if not password:
        raise IntegrityError("this baseline is password-protected; a password is required")
    key = _derive_mac_key(password, baseline.auth.kdf, bytes.fromhex(baseline.auth.salt), progress)
    expected = _compute_mac(baseline, key)
    if not hmac.compare_digest(expected, baseline.auth.mac):
        raise BaselineAuthError(
            "baseline authentication failed: the password is incorrect, or the baseline "
            "file has been altered")


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #

def _scan(target: Path, skip: Optional[Path] = None) -> List[Tuple[str, Path, int]]:
    """List ``(relative_posix_path, absolute_path, size)`` for every file."""
    if target.is_file():
        return [(target.name, target, target.stat().st_size)]

    skip_norm = os.path.normcase(os.path.abspath(skip)) if skip else None
    found: List[Tuple[str, Path, int]] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if skip_norm and os.path.normcase(os.path.abspath(full)) == skip_norm:
                continue
            if not full.is_file():  # broken symlink, device, etc.
                continue
            found.append((full.relative_to(target).as_posix(), full, full.stat().st_size))
    return found


def default_baseline_path(target: PathLike) -> Path:
    target = Path(target)
    return target.with_name(target.name + BASELINE_SUFFIX)


# --------------------------------------------------------------------------- #
# Create / check baselines
# --------------------------------------------------------------------------- #

def create_baseline(target: PathLike, manifest: Optional[PathLike] = None, *,
                    algorithm: str = DEFAULT_ALGORITHM, password: Optional[str] = None,
                    overwrite: bool = False, chunk_size: int = CHUNK_SIZE,
                    progress: Optional[ProgressCallback] = None) -> Tuple[Baseline, Path]:
    """Hash ``target`` (a file or a folder) and write a baseline file.

    With ``password`` the baseline is sealed with an HMAC so that any later edit
    to it is detected. Returns ``(baseline, manifest_path)``.
    """
    _check_algorithm(algorithm)
    target = Path(target)
    if not target.exists():
        raise IntegrityError(f"target not found: {target}")
    manifest_path = Path(manifest) if manifest else default_baseline_path(target)
    if manifest_path.exists() and not overwrite:
        raise cenc.OutputExistsError(
            f"baseline file already exists: {manifest_path} (use --force to overwrite)")
    if manifest_path.resolve() == target.resolve():
        raise IntegrityError("the baseline file must be different from the target")
    if password is not None and not password:
        raise IntegrityError("password must not be empty")

    entries = _scan(target, skip=manifest_path)
    if not entries:
        raise IntegrityError(f"no files found to record in {target}")
    for rel, _full, _size in entries:
        if "\\" in rel:
            raise IntegrityError(f"unsupported file name (contains a backslash): {rel}")

    total = sum(size for _r, _f, size in entries)
    done = 0
    records: List[FileRecord] = []
    for rel, full, size in entries:
        phase = f"Hashing {rel}"
        _report(progress, phase, done, total)

        def on_bytes(n: int, _phase: str = phase) -> None:
            nonlocal done
            done += n
            _report(progress, _phase, done, total)

        digest = _hash_path(full, algorithm, chunk_size, on_bytes)
        records.append(FileRecord(rel, size, digest))

    baseline = Baseline(
        algorithm=algorithm,
        created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        root=str(target.resolve()),
        is_dir=target.is_dir(),
        files=records,
    )
    if password:
        kdf = cenc.default_version()
        salt = secrets.token_bytes(cenc.SALT_LEN)
        baseline.auth = Auth(kdf, salt.hex())
        key = _derive_mac_key(password, kdf, salt, progress)
        baseline.auth = Auth(kdf, salt.hex(), _compute_mac(baseline, key))

    payload = json.dumps(baseline.to_dict(), indent=2, ensure_ascii=True).encode() + b"\n"
    with cenc._atomic_output(manifest_path, overwrite) as fh:
        fh.write(payload)
    return baseline, manifest_path


@dataclass(frozen=True)
class FileResult:
    path: str
    status: str
    detail: str = ""


@dataclass
class CheckReport:
    target: Path
    algorithm: str
    authenticated: bool  # True only if a password-protected baseline verified
    results: List[FileResult] = field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(1 for r in self.results if r.status == status)

    @property
    def ok(self) -> bool:
        """True if every recorded file is unchanged and nothing was added."""
        return all(r.status == UNCHANGED for r in self.results)

    @property
    def problems(self) -> List[FileResult]:
        return [r for r in self.results if r.status != UNCHANGED]


def check_baseline(manifest: PathLike, target: Optional[PathLike] = None, *,
                   password: Optional[str] = None, chunk_size: int = CHUNK_SIZE,
                   progress: Optional[ProgressCallback] = None) -> CheckReport:
    """Compare the current state of ``target`` with a recorded baseline.

    ``target`` defaults to the location recorded in the baseline. Files are
    reported as unchanged, modified, missing, or (for folders) new.
    """
    manifest_path = Path(manifest)
    baseline = read_baseline(manifest_path)
    authenticate_baseline(baseline, password, progress=progress)

    root = Path(target) if target else Path(baseline.root)
    if not root.exists():
        raise IntegrityError(f"target not found: {root}")
    if baseline.is_dir != root.is_dir():
        kind = "folder" if baseline.is_dir else "file"
        raise IntegrityError(f"the baseline was recorded for a {kind}, but '{root}' is not")

    current = _scan(root, skip=manifest_path)
    by_rel = {rel: (full, size) for rel, full, size in current}

    # Pair each record with a file on disk. A single-file baseline matches the
    # chosen file even if it has since been renamed.
    pairs: List[Tuple[FileRecord, Optional[Tuple[Path, int]]]] = []
    if baseline.is_dir:
        for rec in baseline.files:
            pairs.append((rec, by_rel.get(rec.path)))
    else:
        rec = baseline.files[0]
        pairs.append((rec, (current[0][1], current[0][2]) if current else None))

    # Only files whose size still matches need hashing; a size change is proof enough.
    total = sum(found[1] for rec, found in pairs if found and found[1] == rec.size)
    done = 0
    report = CheckReport(root, baseline.algorithm, authenticated=baseline.protected)

    for rec, found in pairs:
        if found is None:
            report.results.append(FileResult(rec.path, MISSING, "file no longer exists"))
            continue
        full, size = found
        if size != rec.size:
            report.results.append(
                FileResult(rec.path, MODIFIED, f"size changed: {rec.size:,} -> {size:,} bytes"))
            continue
        phase = f"Checking {rec.path}"
        _report(progress, phase, done, total)

        def on_bytes(n: int, _phase: str = phase) -> None:
            nonlocal done
            done += n
            _report(progress, _phase, done, total)

        try:
            actual = _hash_path(full, baseline.algorithm, chunk_size, on_bytes)
        except OSError as exc:
            report.results.append(FileResult(rec.path, ERROR, f"could not read: {exc}"))
            continue
        if hmac.compare_digest(actual, rec.hash):
            report.results.append(FileResult(rec.path, UNCHANGED))
        else:
            report.results.append(FileResult(rec.path, MODIFIED, "contents differ (hash mismatch)"))

    if baseline.is_dir:
        known = {rec.path for rec in baseline.files}
        for rel, _full, size in current:
            if rel not in known:
                report.results.append(
                    FileResult(rel, NEW, f"not in the baseline ({size:,} bytes)"))

    report.results.sort(key=lambda r: r.path)
    return report


# --------------------------------------------------------------------------- #
# Command-line interface
# --------------------------------------------------------------------------- #

def _fmt_size(n: int) -> str:
    size = float(n)
    for unit in ("bytes", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{int(size)} {unit}" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} bytes"  # pragma: no cover


def _cmd_hash(args: argparse.Namespace) -> int:
    if not args.file.is_file():
        raise IntegrityError(f"file not found: {args.file}")
    result = compare_file_hash(args.file, args.expect, args.algorithm)
    print(f"{ALGORITHMS[result.algorithm]}: {result.actual}  {args.file.name}")
    if not result.compared:
        return EXIT_OK
    if result.match:
        print("MATCH: the file matches the expected hash.")
        return EXIT_OK
    print(f"MISMATCH: expected {result.expected}", file=sys.stderr)
    print("The file is NOT identical to the one that hash describes.", file=sys.stderr)
    return EXIT_MISMATCH


def _cmd_baseline(args: argparse.Namespace) -> int:
    password = None
    if args.protect:
        password = getpass("Baseline password: ")
        if not password:
            raise IntegrityError("password must not be empty")
        if getpass("Confirm password: ") != password:
            raise IntegrityError("passwords do not match")
    baseline, path = create_baseline(args.target, args.output, algorithm=args.algorithm,
                                     password=password, overwrite=args.force)
    kind = "folder" if baseline.is_dir else "file"
    print(f"Recorded {len(baseline.files)} file(s) ({_fmt_size(baseline.total_size)}) from the "
          f"{kind} '{args.target}' using {ALGORITHMS[baseline.algorithm]}.")
    print(f"Baseline written to '{path}'"
          + (" (password-protected)." if baseline.protected else "."))
    if not baseline.protected:
        print("Note: this baseline is not password-protected, so someone who can change the "
              "files can also change the baseline. Use --protect to detect that.")
    return EXIT_OK


def _cmd_check(args: argparse.Namespace) -> int:
    baseline = read_baseline(args.manifest)
    password = getpass("Baseline password: ") if baseline.protected else None
    report = check_baseline(args.manifest, args.target, password=password)

    for r in report.results:
        if r.status != UNCHANGED or args.verbose:
            print(f"  {r.status.upper():<9} {r.path}" + (f"  - {r.detail}" if r.detail else ""))
    n = len(report.results)
    print(f"Checked '{report.target}' against baseline ({ALGORITHMS[report.algorithm]}): "
          f"{report.count(UNCHANGED)} unchanged, {report.count(MODIFIED)} modified, "
          f"{report.count(MISSING)} missing, {report.count(NEW)} new"
          + (f", {report.count(ERROR)} unreadable" if report.count(ERROR) else "") + ".")
    if report.authenticated:
        print("Baseline authenticity verified (password correct, baseline unaltered).")
    else:
        print("Note: baseline is not password-protected; it cannot prove it wasn't edited too.")
    if report.ok:
        print(f"OK: all {n} file(s) match the baseline.")
        return EXIT_OK
    print("CHANGES DETECTED.", file=sys.stderr)
    return EXIT_MISMATCH


def build_parser() -> argparse.ArgumentParser:
    algos = sorted(ALGORITHMS)
    parser = argparse.ArgumentParser(
        prog="integrity",
        description="Check file integrity with cryptographic hashes and tamper-evident baselines.")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("hash", help="compute a file's hash, optionally comparing to an expected one")
    p.add_argument("file", type=Path)
    p.add_argument("-a", "--algorithm", choices=algos, default=DEFAULT_ALGORITHM)
    p.add_argument("-e", "--expect", metavar="HASH",
                   help="expected hash to compare against (bare, 'sha256:...' or sha256sum format)")
    p.set_defaults(func=_cmd_hash)

    p = sub.add_parser("baseline", help="record hashes of a file or folder")
    p.add_argument("target", type=Path, help="file or folder to record")
    p.add_argument("-o", "--output", type=Path,
                   help=f"baseline file (default: TARGET{BASELINE_SUFFIX} next to the target)")
    p.add_argument("-a", "--algorithm", choices=algos, default=DEFAULT_ALGORITHM)
    p.add_argument("-p", "--protect", action="store_true",
                   help="seal the baseline with a password so edits to it are detected")
    p.add_argument("-f", "--force", action="store_true", help="overwrite an existing baseline")
    p.set_defaults(func=_cmd_baseline)

    p = sub.add_parser("check", help="compare the current files with a baseline")
    p.add_argument("manifest", type=Path, help="baseline file created by 'baseline'")
    p.add_argument("-t", "--target", type=Path,
                   help="file/folder to check (default: the location recorded in the baseline)")
    p.add_argument("-v", "--verbose", action="store_true", help="also list unchanged files")
    p.set_defaults(func=_cmd_check)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BaselineAuthError as exc:
        print(f"integrity: {exc}", file=sys.stderr)
        return EXIT_BASELINE_AUTH
    except cenc.CencError as exc:
        print(f"integrity: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"integrity: I/O error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\nintegrity: aborted", file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
