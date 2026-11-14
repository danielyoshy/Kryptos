"""Header picture and window icon for the desktop app.

The artwork lives in ``assets/vault_<size>.png`` (pre-scaled copies of one
illustration, with rounded transparent corners). The copy closest to the
display's DPI-adjusted size is used so the picture stays sharp without any
image-processing dependency; Tk only needs its built-in PNG support.

If the assets are missing the app simply runs without a picture.
"""

from __future__ import annotations

import math
import re
import subprocess
import sys
import tempfile
import tkinter as tk
from pathlib import Path
from typing import Optional, Tuple

ASSET_DIR = Path(__file__).resolve().parent / "assets"
SIZES = (64, 96, 128, 144, 192, 256)  # pixel sizes shipped in ASSET_DIR
HEADER_SIZE = 64                      # header picture size at 100% display scaling

IMAGE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico",
)
VIDEO_EXTENSIONS = (
    ".mp4", ".mov", ".avi", ".mkv", ".webm", ".wmv", ".m4v",
    ".flv", ".mpeg", ".mpg", ".3gp", ".ts", ".ogv",
)
PDF_EXTENSIONS = (".pdf",)


def asset_path(size: int) -> Path:
    return ASSET_DIR / f"vault_{size}.png"


def _load(master: tk.Misc, size: int) -> Optional[tk.PhotoImage]:
    try:
        return tk.PhotoImage(master=master, file=str(asset_path(size)))
    except tk.TclError:  # file missing or unreadable
        return None


def header_size_for(master: tk.Misc) -> int:
    """Pick the shipped size closest to the header size at this display's DPI."""
    scale = max(1.0, master.winfo_fpixels("1i") / 96.0)
    target = HEADER_SIZE * scale
    return min(SIZES, key=lambda s: abs(s - target))


def header_image(master: tk.Misc) -> Optional[tk.PhotoImage]:
    """Return the header picture (the caller must keep a reference to it), or None."""
    return _load(master, header_size_for(master))


def set_window_icon(window: tk.Tk) -> Optional[list]:
    """Use the artwork as the window/taskbar icon. Returns the images to keep alive."""
    images = [img for img in (_load(window, 64), _load(window, 128)) if img is not None]
    if images:
        try:
            window.iconphoto(True, *images)
        except tk.TclError:
            return None
    return images or None


def make_image_thumbnail(master: tk.Misc, path: Path,
                         max_side: int = 210) -> Tuple[Optional[tk.PhotoImage], str]:
    """Create a scaled ``tk.PhotoImage`` preview and dimension string for ``path``.

    Tries Tk's native PNG/GIF/PGM/PPM reader first; on Windows falls back to
    ``.NET System.Drawing`` for JPEG/BMP/TIFF/ICO so no external package is needed.
    """
    try:
        full = tk.PhotoImage(master=master, file=str(path))
        w, h = full.width(), full.height()
        step = max(1, math.ceil(max(w, h) / max(1, max_side)))
        thumb = full.subsample(step, step) if step > 1 else full
        return thumb, f"{w} \u00d7 {h} px"
    except tk.TclError:
        pass

    if sys.platform == "win32":
        tmp_fd, tmp_png = tempfile.mkstemp(suffix=".png")
        try:
            import os
            os.close(tmp_fd)
            ps_script = (
                "Add-Type -AssemblyName System.Drawing; "
                "$img = [System.Drawing.Image]::FromFile($args[0]); "
                "$ow = $img.Width; $oh = $img.Height; "
                "$max = [int]$args[2]; "
                "$scale = [Math]::Min(1.0, $max / [double][Math]::Max($ow, $oh)); "
                "$nw = [Math]::Max(1, [int]($ow * $scale)); "
                "$nh = [Math]::Max(1, [int]($oh * $scale)); "
                "$bmp = New-Object System.Drawing.Bitmap $nw, $nh; "
                "$g = [System.Drawing.Graphics]::FromImage($bmp); "
                "$g.InterpolationMode = 'HighQualityBicubic'; "
                "$g.DrawImage($img, 0, 0, $nw, $nh); "
                "$bmp.Save($args[1], [System.Drawing.Imaging.ImageFormat]::Png); "
                "$g.Dispose(); $bmp.Dispose(); $img.Dispose(); "
                "Write-Output \"$ow|$oh\""
            )
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script,
                 str(path), tmp_png, str(max_side)],
                capture_output=True, text=True, timeout=6, creationflags=creationflags,
            )
            if res.returncode == 0 and "|" in res.stdout:
                ow, oh = res.stdout.strip().splitlines()[-1].split("|", 1)
                thumb = tk.PhotoImage(master=master, file=tmp_png)
                return thumb, f"{ow} \u00d7 {oh} px"
        except Exception:  # noqa: BLE001 - preview is purely visual
            pass
        finally:
            try:
                Path(tmp_png).unlink(missing_ok=True)
            except OSError:
                pass

    return None, "Preview unavailable (image bytes loaded)"


def _format_duration_100ns(ticks_100ns: int) -> str:
    total_sec = max(0, round(ticks_100ns / 10_000_000))
    hrs, rem = divmod(total_sec, 3600)
    mins, secs = divmod(rem, 60)
    if hrs:
        return f"{hrs:d}:{mins:02d}:{secs:02d}"
    return f"{mins:02d}:{secs:02d}"


def _make_video_badge(master: tk.Misc, width: int = 164, height: int = 104) -> Optional[tk.PhotoImage]:
    """Render a crisp dark-themed filmstrip + play-button badge with pure Tk."""
    try:
        img = tk.PhotoImage(master=master, width=width, height=height)
    except tk.TclError:
        return None

    img.put("#3a414d", to=(0, 0, width, height))
    img.put("#171a20", to=(1, 1, width - 1, height - 1))

    # Left and right filmstrip rails + sprocket perforations.
    rail_w = 18
    img.put("#20242c", to=(2, 2, 2 + rail_w, height - 2))
    img.put("#20242c", to=(width - 2 - rail_w, 2, width - 2, height - 2))
    hole_h, hole_w = 10, 8
    holes = 5
    gap = (height - 8 - holes * hole_h) // max(1, holes - 1)
    for i in range(holes):
        y0 = 4 + i * (hole_h + gap)
        y1 = min(height - 4, y0 + hole_h)
        img.put("#323844", to=(7, y0, 7 + hole_w, y1))
        img.put("#323844", to=(width - 7 - hole_w, y0, width - 7, y1))

    # Subtle screen frame lines inside the filmstrip rails.
    img.put("#2a303a", to=(2 + rail_w, 1, 3 + rail_w, height - 1))
    img.put("#2a303a", to=(width - 3 - rail_w, 1, width - 2 - rail_w, height - 1))

    # Center circular blue play button with white play triangle.
    cx, cy = width // 2, height // 2
    r_outer, r_inner = 23, 21
    for r, col in ((r_outer, "#2563eb"), (r_inner, "#3b82f6")):
        for dy in range(-r, r + 1):
            dx = int(math.isqrt(r * r - dy * dy))
            img.put(col, to=(cx - dx, cy + dy, cx + dx + 1, cy + dy + 1))

    tx0, tx1 = cx - 6, cx + 10
    span = max(1, tx1 - tx0)
    for tx in range(tx0, tx1 + 1):
        half_h = round(9 * (tx1 - tx) / span)
        img.put("#f8fafc", to=(tx, cy - half_h, tx + 1, cy + half_h + 1))

    return img


def make_video_preview(master: tk.Misc, path: Path) -> Tuple[Optional[tk.PhotoImage], str]:
    """Return a dark filmstrip preview badge and video metadata summary for ``path``."""
    ext_label = (path.suffix.lstrip(".").upper() or "RAW") + " video"
    parts = [ext_label]

    if sys.platform == "win32":
        try:
            ps_script = (
                "$p = $args[0]; "
                "$sh = New-Object -ComObject Shell.Application; "
                "$folder = $sh.Namespace([System.IO.Path]::GetDirectoryName($p)); "
                "$item = $folder.ParseName([System.IO.Path]::GetFileName($p)); "
                "if ($null -ne $item) { "
                "  $w = $item.ExtendedProperty('System.Video.FrameWidth'); "
                "  $h = $item.ExtendedProperty('System.Video.FrameHeight'); "
                "  $d = $item.ExtendedProperty('System.Media.Duration'); "
                "  Write-Output \"$w|$h|$d\" "
                "}"
            )
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script, str(path.resolve())],
                capture_output=True, text=True, timeout=4, creationflags=creationflags,
            )
            if res.returncode == 0 and "|" in res.stdout:
                w_s, h_s, d_s = res.stdout.strip().splitlines()[-1].split("|", 2)
                if w_s.strip().isdigit() and h_s.strip().isdigit():
                    parts.append(f"{w_s.strip()} \u00d7 {h_s.strip()} px")
                if d_s.strip().isdigit() and int(d_s.strip()) > 0:
                    parts.append(_format_duration_100ns(int(d_s.strip())))
        except Exception:  # noqa: BLE001 - metadata probe is optional
            pass

    badge = _make_video_badge(master)
    return badge, " \u00b7 ".join(parts)


def _make_pdf_badge(master: tk.Misc, width: int = 164, height: int = 104) -> Optional[tk.PhotoImage]:
    """Render a crisp dark-themed PDF document preview badge with pure Tk."""
    try:
        img = tk.PhotoImage(master=master, width=width, height=height)
    except tk.TclError:
        return None

    img.put("#3a414d", to=(0, 0, width, height))
    img.put("#171a20", to=(1, 1, width - 1, height - 1))

    # Portrait document page centered in the frame with a folded top-right corner.
    px0, py0, px1, py1 = (width - 68) // 2, 7, (width + 68) // 2, height - 7
    fold = 14
    img.put("#4b5563", to=(px0, py0, px1 - fold, py1))
    img.put("#4b5563", to=(px0, py0 + fold, px1, py1))
    img.put("#232832", to=(px0 + 1, py0 + 1, px1 - fold, py1 - 1))
    img.put("#232832", to=(px0 + 1, py0 + fold, px1 - 1, py1 - 1))
    for i in range(fold):
        img.put("#4b5563", to=(px1 - fold + i, py0 + i, px1 - fold + i + 1, py0 + fold + 1))
        if i > 0:
            img.put("#374151", to=(px1 - fold + 1, py0 + i, px1 - fold + i, py0 + i + 1))

    # Simulated text lines on the page.
    for ly, lw in ((py0 + 18, 34), (py0 + 25, 48), (py0 + 32, 42),
                   (py0 + 70, 46), (py0 + 77, 36)):
        img.put("#3f4756", to=(px0 + 9, ly, px0 + 9 + lw, ly + 3))

    # Red PDF ribbon across the document.
    rx0, ry0, rx1, ry1 = px0 - 8, py0 + 42, px1 + 8, py0 + 63
    img.put("#b91c1c", to=(rx0, ry0, rx1, ry1))
    img.put("#dc2626", to=(rx0 + 1, ry0 + 1, rx1 - 1, ry1 - 1))

    # Pixel-art "PDF" letters (each 4x5 scaled 2x -> 8x10 px).
    glyphs = {
        "P": ("1110", "1001", "1110", "1000", "1000"),
        "D": ("1110", "1001", "1001", "1001", "1110"),
        "F": ("1111", "1000", "1110", "1000", "1000"),
    }
    gx0 = (width - (3 * 8 + 2 * 4)) // 2
    gy0 = ry0 + (ry1 - ry0 - 10) // 2
    for idx, ch in enumerate("PDF"):
        ox = gx0 + idx * 12
        for r_i, row in enumerate(glyphs[ch]):
            for c_i, bit in enumerate(row):
                if bit == "1":
                    img.put("#f8fafc", to=(ox + c_i * 2, gy0 + r_i * 2,
                                           ox + c_i * 2 + 2, gy0 + r_i * 2 + 2))

    return img


_PDF_VERSION_RE = re.compile(rb"%PDF-(\d+\.\d+)")
_PDF_PAGE_RE = re.compile(rb"/Type\s*/Page\b(?![sS])")


def make_pdf_preview(master: tk.Misc, path: Path) -> Tuple[Optional[tk.PhotoImage], str]:
    """Return a dark PDF document preview badge and metadata summary for ``path``."""
    parts = ["PDF document"]
    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            head = f.read(min(size, 4 * 1024 * 1024))
        m_ver = _PDF_VERSION_RE.search(head[:1024])
        if m_ver:
            parts[0] = f"PDF {m_ver.group(1).decode('ascii', errors='ignore')} document"
        if size <= 4 * 1024 * 1024:
            pages = len(_PDF_PAGE_RE.findall(head))
            if pages > 0:
                parts.append(f"{pages} page" if pages == 1 else f"{pages} pages")
    except OSError:
        pass

    badge = _make_pdf_badge(master)
    return badge, " \u00b7 ".join(parts)
