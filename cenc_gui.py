#!/usr/bin/env python3
"""CENC File Vault - desktop GUI for cenc.py (Tkinter, no extra dependencies).

Run with::

    python cenc_gui.py

All cryptography is done by :mod:`cenc`; this module only provides the window.
Long operations run on a worker thread and report back through a queue, so the
window stays responsive and can cancel an operation part-way through.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Optional

try:
    import cenc
    import integrity
    import vault_store
except ImportError as _exc:  # pragma: no cover - environment problem, not a code path to test
    _msg = (f"CENC File Vault could not start:\n\n{_exc}\n\n"
            "Install the requirements with:\n    pip install -r requirements.txt")
    try:
        _root = tk.Tk()
        _root.withdraw()
        messagebox.showerror("CENC File Vault", _msg)
    except Exception:  # noqa: BLE001 - no display available; fall back to the console
        print(_msg, file=sys.stderr)
    raise SystemExit(1)

import cenc_icons

APP_TITLE = "CENC File Vault"
POLL_MS = 50

KDF_ARGON2 = "Argon2id (recommended)"
KDF_PBKDF2 = "PBKDF2-HMAC-SHA256"

ALGO_LABELS = list(integrity.ALGORITHMS.values())
ALGO_BY_LABEL = {label: name for name, label in integrity.ALGORITHMS.items()}

# Dark-gray palette.
DARK_BG = "#23252a"       # window & outer chrome
PANEL_BG = "#2c2f36"      # tab interiors & panels
INPUT_BG = "#1b1d21"      # entries, log, treeview
BUTTON_BG = "#383c45"     # standard buttons & headings
BUTTON_ACTIVE = "#454a56" # hovered buttons & tabs
BORDER_COL = "#3d424d"    # subtle borders
ACCENT = "#2563eb"        # primary action buttons & progress bar
ACCENT_HOVER = "#3b82f6"  # primary action hover
TEXT_MAIN = "#e5e7eb"     # primary foreground
TEXT_SUB = "#9ca3af"      # secondary / hint text
TEXT_DISABLED = "#6b7280" # disabled controls
COLOR_GOOD = "#4ade80"    # bright green on dark gray
COLOR_WARN = "#fbbf24"    # bright amber on dark gray
COLOR_BAD = "#f87171"     # bright coral red on dark gray

# Treeview ordering/colours for baseline check results.
STATUS_ORDER = {integrity.MODIFIED: 0, integrity.MISSING: 1, integrity.NEW: 2,
                integrity.ERROR: 3, integrity.UNCHANGED: 4}
STATUS_COLORS = {integrity.MODIFIED: COLOR_BAD, integrity.MISSING: COLOR_BAD,
                 integrity.NEW: COLOR_WARN, integrity.ERROR: COLOR_BAD,
                 integrity.UNCHANGED: TEXT_SUB}

# Phases that have no byte-count to show; these use an animated bar instead.
INDETERMINATE_PHASES = {"Deriving key", "Deleting original"}


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("bytes", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{int(size)} {unit}" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} bytes"  # pragma: no cover


def clean_path(text: str) -> str:
    """Strip whitespace and the quotes Windows adds with 'Copy as path'."""
    return text.strip().strip('"').strip()


class App(tk.Tk):
    def __init__(self, vault_dir: Optional[Path] = None) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(780, 760)
        self.geometry("860x920")

        self.vault_dir = vault_store.ensure_vault_dir(vault_dir)
        self._queue: "queue.Queue[tuple]" = queue.Queue()
        self._cancel = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._closing = False
        self._last_phase = ""
        self._task_name = ""
        self._action_buttons: list[ttk.Button] = []
        self._autofill: dict[str, str] = {}  # output var name -> last auto value

        self._setup_style()
        self._build_layout()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_job = self.after(POLL_MS, self._poll)
        self.after(100, self._bring_to_front)
        self._log(f"Ready. Encryption: {self._default_kdf_label()}.", "info")

    def _bring_to_front(self) -> None:
        """Make sure the window isn't hidden behind the terminal/Explorer that launched it."""
        self._enable_dark_titlebar()
        self.deiconify()
        self.lift()
        self.attributes("-topmost", True)
        self.after(400, lambda: self.attributes("-topmost", False))
        self.focus_force()

    def _enable_dark_titlebar(self) -> None:
        """Ask Windows 10/11 DWM for a dark window title bar (no-op elsewhere)."""
        if sys.platform != "win32":
            return
        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id()) or self.winfo_id()
            dark = ctypes.c_int(1)
            # DWMWA_USE_IMMERSIVE_DARK_MODE is 20 on Win10 2004+ / Win11 (19 on older builds).
            for attr in (20, 19):
                if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                        hwnd, attr, ctypes.byref(dark), ctypes.sizeof(dark)) == 0:
                    break
        except Exception:  # noqa: BLE001 - purely cosmetic
            pass

    def report_callback_exception(self, exc, val, tb) -> None:  # noqa: ANN001
        """Surface unexpected errors in the UI (stderr is invisible under pythonw)."""
        traceback.print_exception(exc, val, tb)
        try:
            self._log(f"Unexpected error: {val!r}", "err")
            messagebox.showerror("Unexpected error", f"{type(val).__name__}: {val}")
        except tk.TclError:
            pass

    # ------------------------------------------------------------------ #
    # Layout
    # ------------------------------------------------------------------ #

    def _setup_style(self) -> None:
        self.configure(bg=DARK_BG)
        # Style popup Combobox dropdown lists (classic Tk Listbox under the hood).
        self.option_add("*TCombobox*Listbox.background", INPUT_BG)
        self.option_add("*TCombobox*Listbox.foreground", TEXT_MAIN)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(".", background=DARK_BG, foreground=TEXT_MAIN,
                        fieldbackground=INPUT_BG, bordercolor=BORDER_COL,
                        darkcolor=DARK_BG, lightcolor=BORDER_COL,
                        troughcolor=INPUT_BG, selectbackground=ACCENT,
                        selectforeground="#ffffff", insertcolor=TEXT_MAIN,
                        font=("Segoe UI", 9))

        style.configure("TFrame", background=PANEL_BG)
        style.configure("Outer.TFrame", background=DARK_BG)

        style.configure("TLabel", background=PANEL_BG, foreground=TEXT_MAIN)
        style.configure("Outer.TLabel", background=DARK_BG, foreground=TEXT_MAIN)
        style.configure("Title.TLabel", background=DARK_BG, foreground="#ffffff",
                        font=("Segoe UI", 16, "bold"))
        style.configure("OuterSub.TLabel", background=DARK_BG, foreground=TEXT_SUB)
        style.configure("Sub.TLabel", background=PANEL_BG, foreground=TEXT_SUB)
        style.configure("Warn.TLabel", background=PANEL_BG, foreground=COLOR_WARN)
        style.configure("Good.TLabel", background=PANEL_BG, foreground=COLOR_GOOD)
        style.configure("Bad.TLabel", background=PANEL_BG, foreground=COLOR_BAD)
        style.configure("ResultGood.TLabel", background=PANEL_BG, foreground=COLOR_GOOD,
                        font=("Segoe UI", 12, "bold"))
        style.configure("ResultBad.TLabel", background=PANEL_BG, foreground=COLOR_BAD,
                        font=("Segoe UI", 12, "bold"))
        style.configure("ResultNeutral.TLabel", background=PANEL_BG, foreground=TEXT_MAIN,
                        font=("Segoe UI", 12, "bold"))

        style.configure("TLabelframe", background=DARK_BG, bordercolor=BORDER_COL,
                        lightcolor=BORDER_COL, darkcolor=BORDER_COL)
        style.configure("TLabelframe.Label", background=DARK_BG, foreground=TEXT_SUB,
                        font=("Segoe UI", 9, "bold"))

        style.configure("TNotebook", background=DARK_BG, bordercolor=BORDER_COL,
                        lightcolor=BORDER_COL, darkcolor=BORDER_COL, tabmargins=(0, 2, 0, 0))
        style.configure("TNotebook.Tab", background=DARK_BG, foreground=TEXT_SUB,
                        padding=(10, 6), bordercolor=BORDER_COL, lightcolor=BORDER_COL,
                        darkcolor=BORDER_COL)
        style.map("TNotebook.Tab",
                  background=[("selected", PANEL_BG), ("active", BUTTON_BG)],
                  foreground=[("selected", "#ffffff"), ("active", TEXT_MAIN)],
                  lightcolor=[("selected", PANEL_BG), ("active", BORDER_COL)],
                  bordercolor=[("selected", BORDER_COL)],
                  expand=[("selected", (0, 2, 0, 0))])

        style.configure("TEntry", fieldbackground=INPUT_BG, foreground=TEXT_MAIN,
                        insertcolor=TEXT_MAIN, bordercolor=BORDER_COL,
                        lightcolor=BORDER_COL, darkcolor=BORDER_COL, padding=4)
        style.map("TEntry",
                  fieldbackground=[("readonly", INPUT_BG), ("disabled", DARK_BG)],
                  foreground=[("readonly", TEXT_MAIN), ("disabled", TEXT_DISABLED)],
                  bordercolor=[("focus", ACCENT)])

        style.configure("TCombobox", fieldbackground=INPUT_BG, background=BUTTON_BG,
                        foreground=TEXT_MAIN, arrowcolor=TEXT_MAIN,
                        bordercolor=BORDER_COL, lightcolor=BORDER_COL, darkcolor=BORDER_COL,
                        padding=4)
        style.map("TCombobox",
                  fieldbackground=[("readonly", INPUT_BG), ("disabled", DARK_BG)],
                  foreground=[("readonly", TEXT_MAIN), ("disabled", TEXT_DISABLED)],
                  background=[("active", BUTTON_ACTIVE), ("readonly", BUTTON_BG)],
                  bordercolor=[("focus", ACCENT)])

        style.configure("TCheckbutton", background=PANEL_BG, foreground=TEXT_MAIN,
                        indicatorbackground=INPUT_BG, indicatorforeground="#ffffff")
        style.map("TCheckbutton",
                  background=[("active", PANEL_BG)],
                  foreground=[("active", "#ffffff"), ("disabled", TEXT_DISABLED)],
                  indicatorbackground=[("selected", ACCENT), ("active", BUTTON_BG)])

        style.configure("Outer.TCheckbutton", background=DARK_BG, foreground=TEXT_SUB,
                        indicatorbackground=INPUT_BG, indicatorforeground="#ffffff")
        style.map("Outer.TCheckbutton",
                  background=[("active", DARK_BG)],
                  foreground=[("active", "#ffffff"), ("selected", TEXT_MAIN)],
                  indicatorbackground=[("selected", ACCENT), ("active", BUTTON_BG)])

        style.configure("Input.TCheckbutton", background=INPUT_BG, foreground=TEXT_MAIN,
                        indicatorbackground=INPUT_BG, indicatorforeground="#ffffff")
        style.map("Input.TCheckbutton",
                  background=[("active", INPUT_BG)],
                  foreground=[("active", "#ffffff"), ("disabled", TEXT_DISABLED)],
                  indicatorbackground=[("selected", ACCENT), ("active", BUTTON_BG)])

        style.configure("TRadiobutton", background=PANEL_BG, foreground=TEXT_MAIN,
                        indicatorbackground=INPUT_BG, indicatorforeground="#ffffff")
        style.map("TRadiobutton",
                  background=[("active", PANEL_BG)],
                  foreground=[("active", "#ffffff"), ("selected", "#ffffff"),
                              ("disabled", TEXT_DISABLED)],
                  indicatorbackground=[("selected", ACCENT), ("active", BUTTON_BG)])

        style.configure("TButton", background=BUTTON_BG, foreground=TEXT_MAIN,
                        bordercolor=BORDER_COL, lightcolor=BORDER_COL, darkcolor=BORDER_COL,
                        focuscolor=ACCENT, padding=(10, 4))
        style.map("TButton",
                  background=[("disabled", DARK_BG), ("pressed", ACCENT), ("active", BUTTON_ACTIVE)],
                  foreground=[("disabled", TEXT_DISABLED), ("pressed", "#ffffff")])

        style.configure("Action.TButton", background=ACCENT, foreground="#ffffff",
                        bordercolor=ACCENT, lightcolor=ACCENT_HOVER, darkcolor=ACCENT,
                        font=("Segoe UI", 10, "bold"), padding=(14, 6))
        style.map("Action.TButton",
                  background=[("disabled", BUTTON_BG), ("pressed", "#1d4ed8"),
                              ("active", ACCENT_HOVER)],
                  foreground=[("disabled", TEXT_DISABLED), ("active", "#ffffff")])

        style.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor=INPUT_BG,
                        bordercolor=BORDER_COL, lightcolor=ACCENT, darkcolor=ACCENT)

        style.configure("Treeview", background=INPUT_BG, fieldbackground=INPUT_BG,
                        foreground=TEXT_MAIN, bordercolor=BORDER_COL, rowheight=24)
        style.map("Treeview",
                  background=[("selected", ACCENT)],
                  foreground=[("selected", "#ffffff")])
        style.configure("Treeview.Heading", background=BUTTON_BG, foreground=TEXT_MAIN,
                        bordercolor=BORDER_COL, relief="flat", padding=(6, 4),
                        font=("Segoe UI", 9, "bold"))
        style.map("Treeview.Heading", background=[("active", BUTTON_ACTIVE)])

        style.configure("Vertical.TScrollbar", background=BUTTON_BG, troughcolor=INPUT_BG,
                        arrowcolor=TEXT_SUB, bordercolor=BORDER_COL)
        style.map("Vertical.TScrollbar", background=[("active", BUTTON_ACTIVE)])

    def _build_layout(self) -> None:
        outer = ttk.Frame(self, padding=14, style="Outer.TFrame")
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer, style="Outer.TFrame")
        header.pack(fill="x", pady=(0, 10))
        titles = ttk.Frame(header, style="Outer.TFrame")
        titles.pack(side="left", anchor="w")
        ttk.Label(titles, text="CENC File Vault", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            titles,
            text="AES-256-GCM authenticated encryption with a passphrase-derived key.",
            style="OuterSub.TLabel",
        ).pack(anchor="w")
        # Decorative picture (keeps its own reference so Tk doesn't garbage-collect it).
        self._header_image = cenc_icons.header_image(self)
        self.banner = None
        if self._header_image is not None:
            self.banner = ttk.Label(header, image=self._header_image, style="Outer.TLabel")
            self.banner.pack(side="right")
        self._window_icons = cenc_icons.set_window_icon(self)

        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True)
        self._build_vault_tab()
        self._build_create_tab()
        self._build_encrypt_tab()
        self._build_decrypt_tab()
        self._build_inspect_tab()
        self._build_hash_tab()
        self._build_baseline_tab()
        self.tabs.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        # Shared progress area + Activity toggle.
        prog = ttk.LabelFrame(outer, text="Progress", padding=10)
        prog.pack(fill="x", pady=(12, 0))
        self.status_var = tk.StringVar(value="Idle")
        self.status_label = ttk.Label(prog, textvariable=self.status_var, style="Outer.TLabel")
        self.status_label.grid(row=0, column=0, sticky="w")
        self.show_activity_var = tk.BooleanVar(value=True)
        self.activity_toggle = ttk.Checkbutton(
            prog, text="Show Activity", variable=self.show_activity_var,
            style="Outer.TCheckbutton", command=self._toggle_activity,
        )
        self.activity_toggle.grid(row=0, column=1, sticky="e", padx=(10, 0))
        self.bar = ttk.Progressbar(prog, maximum=100, mode="determinate")
        self.bar.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.cancel_btn = ttk.Button(prog, text="Cancel", command=self._request_cancel,
                                     state="disabled")
        self.cancel_btn.grid(row=1, column=1, padx=(10, 0), pady=(6, 0))
        prog.columnconfigure(0, weight=1)

        # Activity log (uses ttk.Scrollbar so it adopts the dark theme on Windows).
        self.log_frame = ttk.LabelFrame(outer, text="Activity", padding=6)
        self.log_frame.pack(fill="x", pady=(12, 0))
        log_inner = ttk.Frame(self.log_frame, style="Outer.TFrame")
        log_inner.pack(fill="both", expand=True)
        self.log = tk.Text(log_inner, height=6, state="disabled", wrap="word",
                           font=("Consolas", 9), borderwidth=0, highlightthickness=1,
                           highlightbackground=BORDER_COL, highlightcolor=ACCENT,
                           bg=INPUT_BG, fg=TEXT_MAIN, insertbackground=TEXT_MAIN,
                           selectbackground=ACCENT, selectforeground="#ffffff", padx=6, pady=4)
        log_scroll = ttk.Scrollbar(log_inner, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=log_scroll.set)
        self.log.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")
        self.log.tag_configure("info", foreground=TEXT_SUB)
        self.log.tag_configure("ok", foreground=COLOR_GOOD)
        self.log.tag_configure("warn", foreground=COLOR_WARN)
        self.log.tag_configure("err", foreground=COLOR_BAD)

    def _toggle_activity(self) -> None:
        if self.show_activity_var.get():
            self.minsize(780, 760)
            self.log_frame.pack(fill="x", pady=(12, 0))
        else:
            self.log_frame.pack_forget()
            self.minsize(780, 610)

    def _tab(self, title: str) -> ttk.Frame:
        frame = ttk.Frame(self.tabs, padding=14)
        frame.columnconfigure(1, weight=1)
        self.tabs.add(frame, text=f"  {title}  ")
        return frame

    def _path_row(self, parent: ttk.Frame, row: int, label: str, var: tk.StringVar,
                  browse: Callable[[], None]) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=var).grid(row=row, column=1, sticky="ew", padx=8)
        ttk.Button(parent, text="Browse...", command=browse).grid(row=row, column=2)

    def _password_row(self, parent: ttk.Frame, row: int, label: str,
                      var: tk.StringVar) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        entry = ttk.Entry(parent, textvariable=var, show="\u2022")
        entry.grid(row=row, column=1, sticky="ew", padx=8)
        return entry

    def _show_toggle(self, parent: ttk.Frame, row: int, entries: list[ttk.Entry]) -> None:
        show = tk.BooleanVar(value=False)

        def toggle() -> None:
            for e in entries:
                e.configure(show="" if show.get() else "\u2022")

        ttk.Checkbutton(parent, text="Show", variable=show, command=toggle).grid(
            row=row, column=2, sticky="w")

    def _action_button(self, parent: ttk.Frame, row: int, text: str,
                       command: Callable[[], None]) -> ttk.Button:
        btn = ttk.Button(parent, text=text, style="Action.TButton", command=command)
        btn.grid(row=row, column=0, columnspan=3, sticky="e", pady=(14, 0))
        self._action_buttons.append(btn)
        return btn

    # -- Vault Files tab ------------------------------------------------ #

    def _build_vault_tab(self) -> None:
        f = self._tab("Vault Files")
        self._vault_tab_frame = f
        self.v_filter = tk.StringVar(value=vault_store.FILTER_ALL)
        self.v_search = tk.StringVar()
        self.v_move = tk.BooleanVar(value=False)
        self._vault_items_by_id: dict[str, vault_store.VaultItem] = {}

        # Top toolbar: Store file + New file + Move option + Open folder.
        top = ttk.Frame(f)
        top.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 8))
        store_btn = ttk.Button(top, text="Store File...", style="Action.TButton",
                               command=self._store_into_vault)
        store_btn.pack(side="left")
        self._action_buttons.append(store_btn)
        new_btn = ttk.Button(top, text="New File...", command=self._go_to_create_tab)
        new_btn.pack(side="left", padx=(8, 0))
        self._action_buttons.append(new_btn)
        ttk.Checkbutton(
            top, variable=self.v_move,
            text="Move into vault (securely delete original outside)",
        ).pack(side="left", padx=(12, 0))
        ttk.Button(top, text="Open Vault Folder", command=self._open_vault_folder).pack(
            side="right")

        # Filter & search bar.
        filt = ttk.Frame(f)
        filt.grid(row=1, column=0, columnspan=3, sticky="ew", pady=4)
        ttk.Label(filt, text="Show:").pack(side="left")
        for label, val in (("All Files", vault_store.FILTER_ALL),
                           ("Encrypted (.enc)", vault_store.FILTER_ENCRYPTED),
                           ("Unencrypted", vault_store.FILTER_UNENCRYPTED)):
            ttk.Radiobutton(filt, text=label, value=val, variable=self.v_filter,
                            command=self._refresh_vault).pack(side="left", padx=(10, 0))

        ttk.Entry(filt, textvariable=self.v_search, width=22).pack(side="right")
        ttk.Label(filt, text="Search:").pack(side="right", padx=(12, 6))
        self.v_search.trace_add("write", lambda *_: self._refresh_vault())

        self.v_summary = ttk.Label(f, text="", style="Sub.TLabel")
        self.v_summary.grid(row=2, column=0, columnspan=3, sticky="w", pady=(4, 4))

        # Stored files table.
        tree_frame = ttk.Frame(f)
        tree_frame.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=(2, 8))
        f.rowconfigure(3, weight=1)
        cols = ("status", "name", "size", "detail", "modified")
        self.v_tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                   height=9, selectmode="browse")
        headings = (
            ("status", "Status", 105),
            ("name", "File Name", 220),
            ("size", "Size", 85),
            ("detail", "Format / Type", 215),
            ("modified", "Modified", 135),
        )
        for col, title, width in headings:
            self.v_tree.heading(col, text=title)
            self.v_tree.column(col, width=width, anchor="w")
        v_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.v_tree.yview)
        self.v_tree.configure(yscrollcommand=v_scroll.set)
        self.v_tree.pack(side="left", fill="both", expand=True)
        v_scroll.pack(side="right", fill="y")
        self.v_tree.tag_configure(vault_store.FILTER_ENCRYPTED, foreground=COLOR_GOOD)
        self.v_tree.tag_configure(vault_store.FILTER_UNENCRYPTED, foreground=COLOR_WARN)
        self.v_tree.bind("<<TreeviewSelect>>", lambda _e: self._update_vault_buttons())
        self.v_tree.bind("<Double-1>", lambda _e: self._vault_primary_action())

        # Bottom action bar for selected stored file.
        act = ttk.Frame(f)
        act.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(2, 0))
        self.v_enc_btn = ttk.Button(act, text="Encrypt Selected",
                                    command=self._vault_send_to_encrypt, state="disabled")
        self.v_enc_btn.pack(side="left")
        self.v_dec_btn = ttk.Button(act, text="Decrypt Selected",
                                    command=self._vault_send_to_decrypt, state="disabled")
        self.v_dec_btn.pack(side="left", padx=(6, 0))
        self.v_ins_btn = ttk.Button(act, text="Inspect / Hash",
                                    command=self._vault_send_to_inspect, state="disabled")
        self.v_ins_btn.pack(side="left", padx=(6, 0))
        self.v_exp_btn = ttk.Button(act, text="Export Copy...",
                                    command=self._vault_export_selected, state="disabled")
        self.v_exp_btn.pack(side="left", padx=(6, 0))

        ttk.Button(act, text="Refresh", command=self._refresh_vault).pack(side="right")
        self.v_del_btn = ttk.Button(act, text="Delete from Vault",
                                    command=self._vault_delete_selected, state="disabled")
        self.v_del_btn.pack(side="right", padx=(0, 8))

        self._refresh_vault()

    def _on_tab_changed(self, _event: object = None) -> None:
        if self.tabs.select() == str(self._vault_tab_frame):
            self._refresh_vault()

    def _selected_vault_item(self) -> Optional[vault_store.VaultItem]:
        sel = self.v_tree.selection()
        return self._vault_items_by_id.get(sel[0]) if sel else None

    def _update_vault_buttons(self) -> None:
        item = self._selected_vault_item()
        if item is None or self.busy:
            self.v_enc_btn.configure(state="disabled", text="Encrypt Selected")
            for b in (self.v_dec_btn, self.v_ins_btn, self.v_exp_btn, self.v_del_btn):
                b.configure(state="disabled")
            return
        self.v_enc_btn.configure(
            state="normal",
            text="Add Layer (.enc)" if item.encrypted else "Encrypt Selected",
        )
        self.v_dec_btn.configure(state="normal" if item.encrypted else "disabled")
        self.v_ins_btn.configure(state="normal")
        self.v_exp_btn.configure(state="normal")
        self.v_del_btn.configure(state="normal")

    def _refresh_vault(self) -> None:
        prev = self._selected_vault_item()
        prev_name = prev.name if prev else None

        all_items = vault_store.list_vault_items(self.vault_dir, filter_mode=vault_store.FILTER_ALL)
        n_enc = sum(1 for it in all_items if it.encrypted)
        n_plain = len(all_items) - n_enc

        shown = vault_store.list_vault_items(
            self.vault_dir,
            filter_mode=self.v_filter.get(),
            query=self.v_search.get(),
        )
        self.v_tree.delete(*self.v_tree.get_children())
        self._vault_items_by_id.clear()
        reselect_iid = None
        for item in shown:
            badge = "ENCRYPTED" if item.encrypted else "UNENCRYPTED"
            iid = self.v_tree.insert(
                "", "end",
                values=(badge, item.name, human_size(item.size), item.detail, item.modified_iso),
                tags=(item.status,),
            )
            self._vault_items_by_id[iid] = item
            if item.name == prev_name:
                reselect_iid = iid

        if reselect_iid is not None:
            self.v_tree.selection_set(reselect_iid)
        self.v_summary.configure(
            text=f"Vault storage ({self.vault_dir.name}): {len(all_items)} total  \u2022  "
                 f"{n_enc} encrypted  \u2022  {n_plain} unencrypted  "
                 f"(showing {len(shown)})"
        )
        self._update_vault_buttons()

    def _store_into_vault(self) -> None:
        paths = filedialog.askopenfilenames(title="Choose file(s) to store in the vault")
        if not paths:
            return
        move = self.v_move.get()
        if move and not messagebox.askokcancel(
                "Move into vault?",
                f"{len(paths)} file(s) will be copied into the vault and their outside "
                "originals will be overwritten and deleted.\n\nContinue?"):
            return

        stored = 0
        for raw in paths:
            src = Path(raw)
            dst = self.vault_dir / src.name
            overwrite = False
            if dst.exists() and src.resolve() != dst.resolve():
                if not messagebox.askyesno(
                        "File exists in vault",
                        f"'{dst.name}' is already stored in the vault. Replace it?"):
                    continue
                overwrite = True
            try:
                item = vault_store.store_file(src, self.vault_dir, move=move, overwrite=overwrite)
                stored += 1
                verb = "Moved" if move else "Stored"
                self._log(f"{verb} '{item.name}' into vault ({item.status}).", "ok")
            except cenc.SourceRemovalError as exc:
                stored += 1
                self._log(str(exc), "warn")
                messagebox.showwarning("Original not deleted", str(exc))
            except (cenc.CencError, OSError) as exc:
                self._log(f"Could not store '{src.name}': {exc}", "err")
                messagebox.showerror("Store failed", str(exc))

        self._refresh_vault()
        if stored:
            self.status_var.set(f"Stored {stored} file(s) in vault")

    def _open_vault_folder(self) -> None:
        vault_store.ensure_vault_dir(self.vault_dir)
        try:
            if sys.platform == "win32":
                os.startfile(str(self.vault_dir))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                import subprocess
                subprocess.Popen(["open", str(self.vault_dir)])
            else:
                import subprocess
                subprocess.Popen(["xdg-open", str(self.vault_dir)])
        except OSError as exc:
            self._error("Could not open folder", str(exc))

    def _select_tab(self, index: int) -> None:
        self.tabs.select(index)

    def _vault_primary_action(self) -> None:
        item = self._selected_vault_item()
        if item is None or self.busy:
            return
        if item.encrypted:
            self._vault_send_to_decrypt()
        else:
            self._vault_send_to_encrypt()

    def _vault_send_to_encrypt(self) -> None:
        item = self._selected_vault_item()
        if item is None:
            return
        self.enc_layers.set(1)
        self.enc_in.set(str(item.path))
        self.tabs.select(self._encrypt_tab_frame)
        if item.encrypted:
            self.status_var.set(
                f"Selected '{item.name}' to add encryption layer #{item.layers + 1}"
            )
        else:
            self.status_var.set(f"Selected '{item.name}' for encryption")

    def _vault_send_to_decrypt(self) -> None:
        item = self._selected_vault_item()
        if item is None or not item.encrypted:
            return
        self.dec_in.set(str(item.path))
        self.tabs.select(self._decrypt_tab_frame)
        self.status_var.set(f"Selected '{item.name}' for decryption")

    def _vault_send_to_inspect(self) -> None:
        item = self._selected_vault_item()
        if item is None:
            return
        if item.encrypted:
            self.ins_in.set(str(item.path))
            self.tabs.select(self._inspect_tab_frame)
        else:
            self.h_in.set(str(item.path))
            self.tabs.select(self._hash_tab_frame)

    def _go_to_create_tab(self) -> None:
        self.tabs.select(self._create_tab_frame)
        self.c_name_entry.focus_set()

    def _vault_export_selected(self) -> None:
        item = self._selected_vault_item()
        if item is None:
            return
        dst_str = filedialog.asksaveasfilename(
            title="Export copy of stored file",
            initialfile=item.name,
        )
        if not dst_str:
            return
        dst = Path(dst_str)
        try:
            vault_store.export_file(item.path, dst, self.vault_dir, overwrite=True)
            self._log(f"Exported copy of '{item.name}' -> '{dst}'.", "ok")
            self.status_var.set(f"Exported '{item.name}'")
        except (cenc.CencError, OSError) as exc:
            self._log(f"Export failed: {exc}", "err")
            self._error("Export failed", str(exc))

    def _vault_delete_selected(self) -> None:
        item = self._selected_vault_item()
        if item is None:
            return
        if not messagebox.askokcancel(
                "Delete from vault?",
                f"'{item.name}' will be overwritten with random bytes and permanently "
                "removed from the vault.\n\nContinue?"):
            return
        try:
            vault_store.remove_stored_file(item.path, self.vault_dir, secure=True)
            self._log(f"Securely deleted '{item.name}' from vault.", "ok")
            self.status_var.set(f"Deleted '{item.name}' from vault")
            self._refresh_vault()
        except (cenc.CencError, OSError) as exc:
            self._log(f"Delete failed: {exc}", "err")
            self._error("Delete failed", str(exc))

    # -- Create File tab ------------------------------------------------ #

    def _build_create_tab(self) -> None:
        f = self._tab("Create File")
        self._create_tab_frame = f
        self.c_name = tk.StringVar(value="secret_note.txt")
        self.c_dir = tk.StringVar(value=str(self.vault_dir))
        self.c_encrypt_now = tk.BooleanVar(value=True)
        self.c_delete_src_img = tk.BooleanVar(value=True)
        self.c_pw = tk.StringVar()
        self.c_pw2 = tk.StringVar()
        self._c_media_kind: Optional[str] = None  # None | "image" | "video" | "pdf"
        self._c_media_path: Optional[Path] = None
        self._c_media_thumb: Optional[tk.PhotoImage] = None
        self._c_image_path: Optional[Path] = None
        self._c_image_thumb: Optional[tk.PhotoImage] = None
        self._c_video_path: Optional[Path] = None
        self._c_video_thumb: Optional[tk.PhotoImage] = None
        self._c_pdf_path: Optional[Path] = None
        self._c_pdf_thumb: Optional[tk.PhotoImage] = None

        ttk.Label(f, text="File name").grid(row=0, column=0, sticky="w", pady=4)
        self.c_name_entry = ttk.Entry(f, textvariable=self.c_name)
        self.c_name_entry.grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Label(f, text="e.g. notes.txt, doc.pdf, photo.png, clip.mp4", style="Sub.TLabel").grid(
            row=0, column=2, sticky="w")

        ttk.Label(f, text="Store in folder").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.c_dir).grid(row=1, column=1, sticky="ew", padx=8)
        dir_btns = ttk.Frame(f)
        dir_btns.grid(row=1, column=2, sticky="w")
        ttk.Button(dir_btns, text="Browse...", command=self._browse_c_dir).pack(side="left")
        ttk.Button(dir_btns, text="Use Vault",
                   command=lambda: self.c_dir.set(str(self.vault_dir))).pack(
            side="left", padx=(4, 0))

        # Source toolbar: switch between typing text or uploading an image / video / PDF.
        src_bar = ttk.Frame(f)
        src_bar.grid(row=2, column=1, columnspan=2, sticky="ew", padx=(8, 0), pady=(6, 2))
        self.c_upload_img_btn = ttk.Button(
            src_bar, text="Upload Image...", command=self._upload_create_image,
        )
        self.c_upload_img_btn.pack(side="left")
        self.c_upload_vid_btn = ttk.Button(
            src_bar, text="Upload Video...", command=self._upload_create_video,
        )
        self.c_upload_vid_btn.pack(side="left", padx=(8, 0))
        self.c_upload_pdf_btn = ttk.Button(
            src_bar, text="Upload PDF...", command=self._upload_create_pdf,
        )
        self.c_upload_pdf_btn.pack(side="left", padx=(8, 0))
        self.c_remove_img_btn = ttk.Button(
            src_bar, text="Switch to Text Editor", command=self._clear_uploaded_media,
            state="disabled",
        )
        self.c_remove_img_btn.pack(side="left", padx=(8, 0))
        self.c_mode_lbl = ttk.Label(
            src_bar, text="Mode: Text editor",
            style="Sub.TLabel",
        )
        self.c_mode_lbl.pack(side="right")

        self.c_content_lbl = ttk.Label(f, text="File contents")
        self.c_content_lbl.grid(row=3, column=0, sticky="nw", pady=(4, 4))

        # Container holding either the text editor or the uploaded media preview card.
        self.c_body = ttk.Frame(f)
        self.c_body.grid(row=3, column=1, columnspan=2, sticky="nsew", padx=(8, 0), pady=(4, 4))
        f.rowconfigure(3, weight=1)

        self.c_editor_frame = ttk.Frame(self.c_body)
        self.c_editor_frame.pack(fill="both", expand=True)
        self.c_text = tk.Text(self.c_editor_frame, height=8, wrap="word", font=("Consolas", 10),
                              borderwidth=0, highlightthickness=1,
                              highlightbackground=BORDER_COL, highlightcolor=ACCENT,
                              bg=INPUT_BG, fg=TEXT_MAIN, insertbackground=TEXT_MAIN,
                              selectbackground=ACCENT, selectforeground="#ffffff",
                              padx=8, pady=6, undo=True)
        c_scroll = ttk.Scrollbar(self.c_editor_frame, orient="vertical", command=self.c_text.yview)
        self.c_text.configure(yscrollcommand=c_scroll.set)
        self.c_text.pack(side="left", fill="both", expand=True)
        c_scroll.pack(side="right", fill="y")

        # Image preview card (shown when an image is uploaded).
        self.c_img_frame = tk.Frame(self.c_body, bg=INPUT_BG, highlightthickness=1,
                                    highlightbackground=BORDER_COL)
        self.c_img_preview = tk.Label(self.c_img_frame, bg=INPUT_BG, fg=TEXT_SUB)
        self.c_img_preview.pack(side="left", padx=14, pady=10)
        img_meta = tk.Frame(self.c_img_frame, bg=INPUT_BG)
        img_meta.pack(side="left", fill="both", expand=True, padx=(4, 14), pady=12)
        self.c_img_info = tk.Label(img_meta, bg=INPUT_BG, fg=TEXT_MAIN, justify="left",
                                   anchor="w", font=("Consolas", 9))
        self.c_img_info.pack(anchor="w", pady=(0, 8))
        self.c_del_img_chk = tk.Label(
            img_meta, bg=INPUT_BG, fg=TEXT_SUB, justify="left", anchor="w",
            font=("Segoe UI", 9),
            text="Original uploaded file is automatically deleted after encrypting.",
        )
        self.c_del_img_chk.pack(anchor="w")

        self.c_enc_chk = ttk.Checkbutton(
            f, variable=self.c_encrypt_now, command=self._toggle_create_encrypt_fields,
            text="Encrypt immediately as .enc (plaintext is never written to disk)",
        )
        self.c_enc_chk.grid(row=4, column=0, columnspan=3, sticky="w", pady=(6, 2))

        self.c_pw_entry = self._password_row(f, 5, "Password", self.c_pw)
        self.c_pw2_entry = self._password_row(f, 6, "Confirm password", self.c_pw2)
        self._show_toggle(f, 5, [self.c_pw_entry, self.c_pw2_entry])

        kdfs = [KDF_ARGON2, KDF_PBKDF2] if cenc.argon2_available() else [KDF_PBKDF2]
        self.c_kdf = tk.StringVar(value=kdfs[0])
        self.c_layers = tk.IntVar(value=1)
        ttk.Label(f, text="Key derivation").grid(row=7, column=0, sticky="w", pady=4)
        c_kdf_row = ttk.Frame(f)
        c_kdf_row.grid(row=7, column=1, columnspan=2, sticky="w", padx=8)
        self.c_kdf_combo = ttk.Combobox(c_kdf_row, textvariable=self.c_kdf, values=kdfs,
                                        state="readonly", width=26)
        self.c_kdf_combo.pack(side="left")
        ttk.Label(c_kdf_row, text="Encryption layers:").pack(side="left", padx=(18, 6))
        self.c_layers_spin = ttk.Spinbox(
            c_kdf_row, from_=1, to=10, width=4, textvariable=self.c_layers,
        )
        self.c_layers_spin.pack(side="left")
        ttk.Label(c_kdf_row, text="(1 = .enc, 2 = .enc.enc, ...)",
                  style="Sub.TLabel").pack(side="left", padx=(6, 0))

        act = ttk.Frame(f)
        act.grid(row=8, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        self.c_clear_btn = ttk.Button(act, text="Clear", command=self._clear_create_editor)
        self.c_clear_btn.pack(side="left")
        self.c_submit_btn = ttk.Button(act, text="Create & Encrypt (.enc)",
                                       style="Action.TButton", command=self._start_create_file)
        self.c_submit_btn.pack(side="right")
        self._action_buttons.append(self.c_submit_btn)

    def _browse_c_dir(self) -> None:
        initial = clean_path(self.c_dir.get()) or str(self.vault_dir)
        chosen = filedialog.askdirectory(title="Choose folder to store the file",
                                         initialdir=initial)
        if chosen:
            self.c_dir.set(str(Path(chosen)))

    def _load_create_image(self, path: Path) -> None:
        if not path.is_file():
            return self._error("Image not found", f"Could not find image: {path}")
        size = path.stat().st_size
        thumb, dims = cenc_icons.make_image_thumbnail(self, path, max_side=170)
        self._c_media_kind = "image"
        self._c_media_path = path
        self._c_media_thumb = thumb
        self._c_image_path = path
        self._c_image_thumb = thumb
        self._c_video_path = None
        self._c_video_thumb = None
        self._c_pdf_path = None
        self._c_pdf_thumb = None

        self.c_name.set(path.name)
        if thumb is not None:
            self.c_img_preview.configure(image=thumb, text="")
        else:
            self.c_img_preview.configure(image="", text="[Image Loaded]")
        self.c_img_info.configure(
            text=f"Uploaded:   {path.name}\n"
                 f"Dimensions: {dims}\n"
                 f"Size:       {human_size(size)}\n"
                 f"Source:     {path.parent}"
        )
        self.c_editor_frame.pack_forget()
        self.c_img_frame.pack(fill="both", expand=True)
        self.c_content_lbl.configure(text="Uploaded image")
        self.c_remove_img_btn.configure(state="normal")
        self.c_mode_lbl.configure(text=f"Mode: Image ({path.suffix.lower() or 'binary'})")
        self._toggle_create_encrypt_fields()

    def _upload_create_image(self) -> None:
        exts = " ".join(f"*{e}" for e in cenc_icons.IMAGE_EXTENSIONS)
        chosen = filedialog.askopenfilename(
            title="Choose an image to upload and encrypt",
            filetypes=[
                ("Image files", exts),
                ("All files", "*.*"),
            ],
        )
        if chosen:
            self._load_create_image(Path(chosen))

    def _load_create_video(self, path: Path) -> None:
        if not path.is_file():
            return self._error("Video not found", f"Could not find video: {path}")
        size = path.stat().st_size
        badge, details = cenc_icons.make_video_preview(self, path)
        self._c_media_kind = "video"
        self._c_media_path = path
        self._c_media_thumb = badge
        self._c_video_path = path
        self._c_video_thumb = badge
        self._c_image_path = None
        self._c_image_thumb = None
        self._c_pdf_path = None
        self._c_pdf_thumb = None

        self.c_name.set(path.name)
        if badge is not None:
            self.c_img_preview.configure(image=badge, text="")
        else:
            self.c_img_preview.configure(image="", text="[Video Loaded]")
        self.c_img_info.configure(
            text=f"Uploaded:   {path.name}\n"
                 f"Format:     {details}\n"
                 f"Size:       {human_size(size)}\n"
                 f"Source:     {path.parent}"
        )
        self.c_editor_frame.pack_forget()
        self.c_img_frame.pack(fill="both", expand=True)
        self.c_content_lbl.configure(text="Uploaded video")
        self.c_remove_img_btn.configure(state="normal")
        self.c_mode_lbl.configure(text=f"Mode: Video ({path.suffix.lower() or 'binary'})")
        self._toggle_create_encrypt_fields()

    def _upload_create_video(self) -> None:
        exts = " ".join(f"*{e}" for e in cenc_icons.VIDEO_EXTENSIONS)
        chosen = filedialog.askopenfilename(
            title="Choose a video to upload and encrypt",
            filetypes=[
                ("Video files", exts),
                ("All files", "*.*"),
            ],
        )
        if chosen:
            self._load_create_video(Path(chosen))

    def _load_create_pdf(self, path: Path) -> None:
        if not path.is_file():
            return self._error("PDF not found", f"Could not find PDF: {path}")
        size = path.stat().st_size
        badge, details = cenc_icons.make_pdf_preview(self, path)
        self._c_media_kind = "pdf"
        self._c_media_path = path
        self._c_media_thumb = badge
        self._c_pdf_path = path
        self._c_pdf_thumb = badge
        self._c_image_path = None
        self._c_image_thumb = None
        self._c_video_path = None
        self._c_video_thumb = None

        self.c_name.set(path.name)
        if badge is not None:
            self.c_img_preview.configure(image=badge, text="")
        else:
            self.c_img_preview.configure(image="", text="[PDF Loaded]")
        self.c_img_info.configure(
            text=f"Uploaded:   {path.name}\n"
                 f"Document:   {details}\n"
                 f"Size:       {human_size(size)}\n"
                 f"Source:     {path.parent}"
        )
        self.c_editor_frame.pack_forget()
        self.c_img_frame.pack(fill="both", expand=True)
        self.c_content_lbl.configure(text="Uploaded PDF")
        self.c_remove_img_btn.configure(state="normal")
        self.c_mode_lbl.configure(text=f"Mode: PDF ({path.suffix.lower() or '.pdf'})")
        self._toggle_create_encrypt_fields()

    def _upload_create_pdf(self) -> None:
        exts = " ".join(f"*{e}" for e in cenc_icons.PDF_EXTENSIONS)
        chosen = filedialog.askopenfilename(
            title="Choose a PDF file to upload and encrypt",
            filetypes=[
                ("PDF documents", exts),
                ("All files", "*.*"),
            ],
        )
        if chosen:
            self._load_create_pdf(Path(chosen))

    def _clear_uploaded_media(self) -> None:
        self._c_media_kind = None
        self._c_media_path = None
        self._c_media_thumb = None
        self._c_image_path = None
        self._c_image_thumb = None
        self._c_video_path = None
        self._c_video_thumb = None
        self._c_pdf_path = None
        self._c_pdf_thumb = None
        self.c_delete_src_img.set(True)
        self.c_img_preview.configure(image="", text="")
        self.c_img_frame.pack_forget()
        self.c_editor_frame.pack(fill="both", expand=True)
        self.c_content_lbl.configure(text="File contents")
        self.c_remove_img_btn.configure(state="disabled")
        self.c_mode_lbl.configure(text="Mode: Text editor")
        if self.c_name.get().lower().endswith(
                cenc_icons.IMAGE_EXTENSIONS
                + cenc_icons.VIDEO_EXTENSIONS
                + cenc_icons.PDF_EXTENSIONS):
            self.c_name.set("secret_note.txt")
        self._toggle_create_encrypt_fields()

    def _clear_uploaded_image(self) -> None:
        self._clear_uploaded_media()

    def _toggle_create_encrypt_fields(self) -> None:
        enc = self.c_encrypt_now.get()
        kind = self._c_media_kind
        has_media = kind is not None
        state = "normal" if enc else "disabled"
        self.c_pw_entry.configure(state=state)
        self.c_pw2_entry.configure(state=state)
        self.c_kdf_combo.configure(state="readonly" if enc else "disabled")
        self.c_layers_spin.configure(state="normal" if enc else "disabled")
        if kind == "pdf":
            self.c_del_img_chk.configure(
                text=("Original uploaded PDF will be automatically deleted after encrypting."
                      if enc else "Unencrypted copy will be saved to the target folder.")
            )
            self.c_enc_chk.configure(
                text="Encrypt uploaded PDF immediately as .enc"
            )
            self.c_submit_btn.configure(
                text="Encrypt & Store PDF (.enc)" if enc else "Store Unencrypted PDF"
            )
        elif kind == "video":
            self.c_del_img_chk.configure(
                text=("Original uploaded video will be automatically deleted after encrypting."
                      if enc else "Unencrypted copy will be saved to the target folder.")
            )
            self.c_enc_chk.configure(
                text="Encrypt uploaded video immediately as .enc"
            )
            self.c_submit_btn.configure(
                text="Encrypt & Store Video (.enc)" if enc else "Store Unencrypted Video"
            )
        elif kind == "image":
            self.c_del_img_chk.configure(
                text=("Original uploaded image will be automatically deleted after encrypting."
                      if enc else "Unencrypted copy will be saved to the target folder.")
            )
            self.c_enc_chk.configure(
                text="Encrypt uploaded image immediately as .enc"
            )
            self.c_submit_btn.configure(
                text="Encrypt & Store Image (.enc)" if enc else "Store Unencrypted Image"
            )
        else:
            self.c_enc_chk.configure(
                text="Encrypt immediately as .enc (plaintext is never written to disk)"
            )
            self.c_submit_btn.configure(
                text="Create & Encrypt (.enc)" if enc else "Save Unencrypted File"
            )

    def _clear_create_editor(self) -> None:
        if self._c_media_path is not None:
            self._clear_uploaded_media()
        self.c_text.delete("1.0", "end")

    def _editor_text(self) -> str:
        # tk.Text always appends a trailing '\n' at index 'end'; end-1c gives exact user content.
        return self.c_text.get("1.0", "end-1c")

    def _start_create_file(self) -> None:
        media_src = self._c_media_path
        media_kind = self._c_media_kind  # None | "image" | "video" | "pdf"
        if media_kind == "pdf":
            media_noun, media_title, fallback_ext = "PDF", "PDF", ".pdf"
        elif media_kind == "video":
            media_noun, media_title, fallback_ext = "video", "Video", ".mp4"
        else:
            media_noun, media_title, fallback_ext = "image", "Image", ".png"
        if media_src is not None:
            default_ext = media_src.suffix or fallback_ext
        else:
            default_ext = ".txt"
        try:
            clean_name = vault_store.validate_filename(self.c_name.get(), default_ext=default_ext)
        except vault_store.VaultError as exc:
            return self._error("Invalid file name", str(exc))

        dir_text = clean_path(self.c_dir.get())
        if not dir_text:
            return self._error("No folder", "Choose a folder where the file should be stored.")
        out_dir = Path(dir_text)
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return self._error("Invalid folder", f"Could not create folder '{out_dir}': {exc}")

        if media_src is not None and not media_src.is_file():
            return self._error(
                f"{media_title} missing",
                f"Uploaded {media_noun} is no longer at '{media_src}'.",
            )

        encrypt_now = self.c_encrypt_now.get()

        # --- Unencrypted save (text in memory OR uploaded image/video/PDF streamed) ---
        if not encrypt_now:
            dst = out_dir / clean_name
            overwrite = False
            if dst.exists() and (media_src is None or media_src.resolve() != dst.resolve()):
                if not messagebox.askyesno(
                        "File exists", f"'{dst.name}' already exists in '{out_dir}'. Replace it?"):
                    return
                overwrite = True

            if media_src is not None:
                def work_copy(progress: cenc.ProgressCallback) -> Path:
                    return vault_store.copy_plain_file(
                        media_src, dst, overwrite=overwrite, progress=progress,
                    )

                def ok_copy(_result: object) -> None:
                    self._log(f"Saved unencrypted {media_noun} '{dst}'.", "ok")
                    self.status_var.set(f"Saved '{dst.name}'")
                    self._refresh_vault()
                    self.enc_in.set(str(dst))  # ready to encrypt later if desired

                self._run_task(f"Store {media_title}", work_copy, ok_copy)
                return

            try:
                vault_store.create_plain_file(dst, self._editor_text(), overwrite=overwrite)
            except (cenc.CencError, OSError) as exc:
                self._log(f"Could not save '{dst.name}': {exc}", "err")
                return self._error("Save failed", str(exc))
            self._log(f"Saved unencrypted file '{dst}'.", "ok")
            self.status_var.set(f"Saved '{dst.name}'")
            self._refresh_vault()
            self.enc_in.set(str(dst))  # ready to encrypt later if desired
            return

        # --- Encrypted save (text in memory OR uploaded image/video/PDF streamed) ---
        password, confirm = self.c_pw.get(), self.c_pw2.get()
        if not password:
            return self._error("No password", "Enter a password to encrypt the file.")
        if password != confirm:
            return self._error("Passwords differ", "The two passwords do not match.")

        layers = self._read_layers(self.c_layers)
        if layers == 1 and clean_name.lower().endswith(cenc.ENC_SUFFIX):
            enc_name = clean_name
        else:
            enc_name = clean_name + (cenc.ENC_SUFFIX * layers)
        dst = out_dir / enc_name
        if media_src is not None and media_src.resolve() == dst.resolve():
            return self._error("Same file", "The encrypted output must be a different file.")

        overwrite = False
        if dst.exists():
            if not messagebox.askyesno(
                    "File exists", f"'{dst.name}' already exists in '{out_dir}'. Replace it?"):
                return
            overwrite = True

        version = (cenc.VERSION_PBKDF2 if self.c_kdf.get() == KDF_PBKDF2
                   else cenc.VERSION_ARGON2ID)

        layer_note = f" ({layers} layers)" if layers > 1 else ""
        if media_src is not None:
            delete_src = self.c_delete_src_img.get()

            def work_media(progress: cenc.ProgressCallback) -> Path:
                return cenc.encrypt_file_layers(
                    media_src, dst, password, layers=layers, version=version,
                    overwrite=overwrite, remove_source=delete_src, progress=progress,
                )

            def ok_media(_result: object) -> None:
                extra = f" Original {media_noun} wiped and deleted." if delete_src else ""
                self._log(
                    f"Uploaded and encrypted {media_noun} '{media_src.name}' -> '{dst}'"
                    f"{layer_note}.{extra}",
                    "ok",
                )
                self.status_var.set(f"Encrypted '{dst.name}'{layer_note}")
                self.c_pw.set("")
                self.c_pw2.set("")
                self.c_layers.set(1)
                self._clear_uploaded_media()
                self._last_encrypted_output = dst
                self._update_enc_again_btn()
                self.dec_in.set(str(dst))
                self._refresh_vault()

            self._run_task(f"{media_title} Encryption", work_media, ok_media)
            return

        data = self._editor_text().encode("utf-8")

        def work_txt(progress: cenc.ProgressCallback) -> Path:
            return cenc.encrypt_bytes_layers(
                data, dst, password, layers=layers, version=version,
                overwrite=overwrite, progress=progress,
            )

        def ok_txt(_result: object) -> None:
            self._log(f"Created and encrypted '{dst.name}' -> '{dst}'{layer_note} "
                      "(plaintext never touched disk).", "ok")
            self.status_var.set(f"Created '{dst.name}'{layer_note}")
            self.c_pw.set("")
            self.c_pw2.set("")
            self.c_layers.set(1)
            self._clear_create_editor()
            self._last_encrypted_output = dst
            self._update_enc_again_btn()
            self.dec_in.set(str(dst))
            self._refresh_vault()

        self._run_task("Create & Encrypt", work_txt, ok_txt)

    @staticmethod
    def _read_layers(var: tk.Variable) -> int:
        try:
            val = int(str(var.get()).strip())
        except (ValueError, tk.TclError):
            return 1
        return max(1, min(20, val))

    # -- Encrypt tab ---------------------------------------------------- #

    def _build_encrypt_tab(self) -> None:
        f = self._tab("Encrypt")
        self._encrypt_tab_frame = f
        self.enc_in = tk.StringVar()
        self.enc_out = tk.StringVar()
        self.enc_pw = tk.StringVar()
        self.enc_pw2 = tk.StringVar()
        self.enc_delete = tk.BooleanVar(value=True)
        self.enc_layers = tk.IntVar(value=1)
        self._last_encrypted_output: Optional[Path] = None

        self._path_row(f, 0, "File to encrypt", self.enc_in, self._browse_enc_in)
        self._path_row(f, 1, "Save as", self.enc_out, self._browse_enc_out)
        pw = self._password_row(f, 2, "Password", self.enc_pw)
        pw2 = self._password_row(f, 3, "Confirm password", self.enc_pw2)
        self._show_toggle(f, 2, [pw, pw2])
        self.pw_hint = ttk.Label(f, text="", style="Sub.TLabel")
        self.pw_hint.grid(row=4, column=1, sticky="w", padx=8)
        self.enc_pw.trace_add("write", lambda *_: self._update_pw_hint())

        kdfs = [KDF_ARGON2, KDF_PBKDF2] if cenc.argon2_available() else [KDF_PBKDF2]
        self.enc_kdf = tk.StringVar(value=kdfs[0])
        ttk.Label(f, text="Key derivation").grid(row=5, column=0, sticky="w", pady=4)
        enc_kdf_row = ttk.Frame(f)
        enc_kdf_row.grid(row=5, column=1, columnspan=2, sticky="w", padx=8)
        ttk.Combobox(enc_kdf_row, textvariable=self.enc_kdf, values=kdfs, state="readonly",
                     width=26).pack(side="left")
        ttk.Label(enc_kdf_row, text="Layers to apply:").pack(side="left", padx=(18, 6))
        self.enc_layers_spin = ttk.Spinbox(
            enc_kdf_row, from_=1, to=10, width=4, textvariable=self.enc_layers,
            command=self._on_enc_source_or_layers_changed,
        )
        self.enc_layers_spin.pack(side="left")

        self.enc_layer_info_lbl = ttk.Label(
            f, text="Standard single-layer encryption (.enc) — or select a .enc file to add another layer.",
            style="Sub.TLabel", wraplength=680,
        )
        self.enc_layer_info_lbl.grid(row=6, column=0, columnspan=3, sticky="w", pady=(4, 0))

        ttk.Label(
            f, style="Sub.TLabel", wraplength=680,
            text="Automatic replacement: encrypting automatically deletes the original file and "
                 "replaces it with the .enc file once the encrypted container is verified.",
        ).grid(row=7, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Label(
            f, style="Warn.TLabel", wraplength=640,
            text="If you forget the password, the file cannot be recovered.",
        ).grid(row=8, column=0, columnspan=3, sticky="w", pady=(2, 0))

        act = ttk.Frame(f)
        act.grid(row=9, column=0, columnspan=3, sticky="ew", pady=(12, 0))
        self.enc_again_btn = ttk.Button(
            act, text="Encrypt Output Again (+1 Layer)",
            command=self._queue_next_encrypt_layer, state="disabled",
        )
        self.enc_again_btn.pack(side="left")
        self.enc_submit_btn = ttk.Button(
            act, text="Encrypt", style="Action.TButton", command=self._start_encrypt,
        )
        self.enc_submit_btn.pack(side="right")
        self._action_buttons.append(self.enc_submit_btn)

        self.enc_in.trace_add("write", lambda *_: self._on_enc_source_or_layers_changed())
        self.enc_layers.trace_add("write", lambda *_: self._on_enc_source_or_layers_changed())
        self.enc_out.trace_add("write", lambda *_: self._update_enc_again_btn())

    def _on_enc_source_or_layers_changed(self) -> None:
        add_layers = self._read_layers(self.enc_layers)
        self._autofill_output(
            "enc_out", self.enc_in, lambda p: str(p) + (cenc.ENC_SUFFIX * add_layers)
        )
        raw = clean_path(self.enc_in.get())
        if not raw:
            self.enc_layer_info_lbl.configure(
                text=(f"Will apply {add_layers} nested encryption layers ({'.enc' * add_layers})."
                      if add_layers > 1
                      else "Standard single-layer encryption (.enc) — or select a .enc file to add another layer."),
                style="Sub.TLabel",
            )
            self._update_enc_again_btn()
            return
        p = Path(raw)
        if cenc.is_cenc_file(p):
            existing = max(1, cenc.count_enc_suffixes(p))
            new_total = existing + add_layers
            self.enc_layer_info_lbl.configure(
                text=(f"Multi-layer mode: '{p.name}' is already encrypted (layer #{existing}). "
                      f"Encrypting will wrap it to layer #{new_total} ({'.enc' * new_total})."),
                style="Good.TLabel",
            )
        elif add_layers > 1:
            self.enc_layer_info_lbl.configure(
                text=f"Multi-layer mode: will wrap '{p.name}' in {add_layers} nested CENC layers ({'.enc' * add_layers}).",
                style="Good.TLabel",
            )
        else:
            self.enc_layer_info_lbl.configure(
                text=f"Will encrypt '{p.name}' into layer #1 ('{p.name}.enc').",
                style="Sub.TLabel",
            )
        self._update_enc_again_btn()

    def _candidate_reencrypt_path(self) -> Optional[Path]:
        for raw in (clean_path(self.enc_out.get()),
                    str(self._last_encrypted_output) if self._last_encrypted_output else ""):
            if raw:
                p = Path(raw)
                if cenc.is_cenc_file(p):
                    return p
        return None

    def _update_enc_again_btn(self) -> None:
        if not hasattr(self, "enc_again_btn"):
            return
        cand = self._candidate_reencrypt_path()
        in_raw = clean_path(self.enc_in.get())
        same = bool(cand and in_raw and Path(in_raw).resolve() == cand.resolve())
        enabled = (not self.busy) and (cand is not None) and (not same)
        self.enc_again_btn.configure(state="normal" if enabled else "disabled")

    def _queue_next_encrypt_layer(self) -> None:
        cand = self._candidate_reencrypt_path()
        if cand is None:
            return
        self.enc_layers.set(1)
        self.enc_in.set(str(cand))
        next_layer = max(1, cenc.count_enc_suffixes(cand)) + 1
        self.status_var.set(f"Queued '{cand.name}' for encryption layer #{next_layer}")

    def _browse_enc_in(self) -> None:
        path = filedialog.askopenfilename(title="Choose a file to encrypt")
        if path:
            self.enc_in.set(str(Path(path)))

    def _browse_enc_out(self) -> None:
        initial = Path(clean_path(self.enc_out.get()) or "")
        path = filedialog.asksaveasfilename(
            title="Save encrypted file as", defaultextension=cenc.ENC_SUFFIX,
            initialfile=initial.name, initialdir=str(initial.parent) if initial.name else None,
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
        if path:
            self.enc_out.set(str(Path(path)))

    def _update_pw_hint(self) -> None:
        n = len(self.enc_pw.get())
        if n == 0:
            self.pw_hint.configure(text="", style="Sub.TLabel")
        elif n < 8:
            self.pw_hint.configure(text="Very short - use a longer passphrase.", style="Bad.TLabel")
        elif n < 12:
            self.pw_hint.configure(text="Okay - 12+ characters (or a few words) is better.",
                                   style="Warn.TLabel")
        else:
            self.pw_hint.configure(text="Good length.", style="Good.TLabel")

    # -- Decrypt tab ---------------------------------------------------- #

    def _build_decrypt_tab(self) -> None:
        f = self._tab("Decrypt")
        self._decrypt_tab_frame = f
        self.dec_in = tk.StringVar()
        self.dec_out = tk.StringVar()
        self.dec_pw = tk.StringVar()
        self.dec_unwrap_all = tk.BooleanVar(value=False)
        self.dec_delete = tk.BooleanVar(value=True)

        self._path_row(f, 0, "Encrypted file", self.dec_in, self._browse_dec_in)
        self._path_row(f, 1, "Restore as", self.dec_out, self._browse_dec_out)
        pw = self._password_row(f, 2, "Password", self.dec_pw)
        self._show_toggle(f, 2, [pw])

        self.dec_layer_lbl = ttk.Label(
            f, style="Sub.TLabel", wraplength=680,
            text="The file is authenticated before anything is saved: a wrong password or a "
                 "modified file produces an error and leaves the .enc file untouched.",
        )
        self.dec_layer_lbl.grid(row=3, column=0, columnspan=3, sticky="w", pady=(8, 2))

        ttk.Checkbutton(
            f, variable=self.dec_unwrap_all, command=self._on_dec_source_or_mode_changed,
            text="Unwrap all encryption layers that use this password (for multi-layer .enc.enc files)",
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(4, 0))
        ttk.Label(
            f, style="Sub.TLabel", wraplength=680,
            text="Automatic replacement: once decrypted and verified, the .enc file is automatically "
                 "deleted and replaced with the restored original file.",
        ).grid(row=5, column=0, columnspan=3, sticky="w", pady=(6, 0))

        self._action_button(f, 6, "Decrypt", self._start_decrypt)
        self.dec_in.trace_add("write", lambda *_: self._on_dec_source_or_mode_changed())

    def _on_dec_source_or_mode_changed(self) -> None:
        unwrap_all = self.dec_unwrap_all.get()
        self._autofill_output(
            "dec_out", self.dec_in,
            lambda p: str(cenc.strip_enc_suffixes(p) if unwrap_all else cenc._default_decrypt_output(p)),
        )
        raw = clean_path(self.dec_in.get())
        if not raw:
            self.dec_layer_lbl.configure(
                text="The file is authenticated before anything is saved: a wrong password or a "
                     "modified file produces an error and no output.",
                style="Sub.TLabel",
            )
            return
        n_enc = cenc.count_enc_suffixes(raw)
        if n_enc > 1:
            self.dec_layer_lbl.configure(
                text=(f"Multi-layer file detected ({n_enc} .enc suffixes). Decrypting peels the outer "
                      f"layer first (and queues the inner .enc layer next), or tick below to unwrap all "
                      "layers sharing this password."),
                style="Good.TLabel",
            )
        else:
            self.dec_layer_lbl.configure(
                text="The file is authenticated before anything is saved: a wrong password or a "
                     "modified file produces an error and no output.",
                style="Sub.TLabel",
            )

    def _browse_dec_in(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose a .enc file",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
        if path:
            self.dec_in.set(str(Path(path)))

    def _browse_dec_out(self) -> None:
        initial = Path(clean_path(self.dec_out.get()) or "")
        path = filedialog.asksaveasfilename(
            title="Restore file as", initialfile=initial.name,
            initialdir=str(initial.parent) if initial.name else None)
        if path:
            self.dec_out.set(str(Path(path)))

    # -- Inspect tab ---------------------------------------------------- #

    def _build_inspect_tab(self) -> None:
        f = self._tab("Inspect / Verify")
        self._inspect_tab_frame = f
        self.ins_in = tk.StringVar()
        self.ins_pw = tk.StringVar()

        self._path_row(f, 0, "Encrypted file", self.ins_in, self._browse_ins_in)
        self.info_var = tk.StringVar(value="Choose a .enc file to see its header "
                                           "(no password needed).")
        self.info_label = ttk.Label(f, textvariable=self.info_var, justify="left",
                                    font=("Consolas", 9), wraplength=680)
        self.info_label.grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 8))
        pw = self._password_row(f, 2, "Password", self.ins_pw)
        self._show_toggle(f, 2, [pw])
        ttk.Label(
            f, style="Sub.TLabel", wraplength=640,
            text="Verify checks the password and the file's integrity without writing "
                 "any decrypted data.",
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(4, 0))
        self._action_button(f, 4, "Verify integrity", self._start_verify)
        self.ins_in.trace_add("write", lambda *_: self._refresh_info())

    def _browse_ins_in(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose a .enc file",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
        if path:
            self.ins_in.set(str(Path(path)))

    def _refresh_info(self) -> None:
        text = clean_path(self.ins_in.get())
        if not text:
            self.info_var.set("Choose a .enc file to see its header (no password needed).")
            self.info_label.configure(style="TLabel")
            return
        try:
            info = cenc.read_container_info(text)
        except (cenc.CencError, OSError) as exc:
            self.info_var.set(f"Cannot read this file: {exc}")
            self.info_label.configure(style="Bad.TLabel")
            return
        h = info.header
        n_layers = max(1, cenc.count_enc_suffixes(text))
        layer_line = (
            f"Layers:   {n_layers} (.enc suffixes — header below is outer layer #{n_layers})\n"
            if n_layers > 1 else ""
        )
        self.info_var.set(
            f"Format:   CENC v{h.version} - {h.suite.name}\n"
            f"{layer_line}"
            f"Payload:  {human_size(info.ciphertext_len)} ciphertext + {cenc.TAG_LEN}-byte tag\n"
            f"Salt:     {h.salt.hex()}\n"
            f"Nonce:    {h.nonce.hex()}")
        self.info_label.configure(style="TLabel")

    # -- Hash Check tab -------------------------------------------------- #

    def _build_hash_tab(self) -> None:
        f = self._tab("Hash Check")
        self._hash_tab_frame = f
        self.h_in = tk.StringVar()
        self.h_algo = tk.StringVar(value=integrity.ALGORITHMS[integrity.DEFAULT_ALGORITHM])
        self.h_expected = tk.StringVar()
        self.h_actual = tk.StringVar()

        self._path_row(f, 0, "File", self.h_in, self._browse_h_in)
        ttk.Label(f, text="Algorithm").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Combobox(f, textvariable=self.h_algo, values=ALGO_LABELS, state="readonly",
                     width=16).grid(row=1, column=1, sticky="w", padx=8)
        ttk.Label(f, text="Expected hash").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.h_expected).grid(
            row=2, column=1, columnspan=2, sticky="ew", padx=8)
        ttk.Label(
            f, style="Sub.TLabel", wraplength=680,
            text="Optional. Paste the checksum published by the source to confirm the file "
                 "is identical. Formats like 'sha256:...' or 'hash  filename' work too. "
                 "Leave blank to just compute the hash.",
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(2, 0))
        self._action_button(f, 4, "Compute / Compare", self._start_hash)

        self.h_result = ttk.Label(f, text="", style="ResultNeutral.TLabel", wraplength=680)
        self.h_result.grid(row=5, column=0, columnspan=3, sticky="w", pady=(14, 4))
        ttk.Label(f, text="Computed hash").grid(row=6, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.h_actual, state="readonly",
                  font=("Consolas", 9)).grid(row=6, column=1, sticky="ew", padx=8)
        ttk.Button(f, text="Copy", command=self._copy_hash).grid(row=6, column=2)

        for var in (self.h_in, self.h_algo, self.h_expected):
            var.trace_add("write", lambda *_: self._clear_hash_result())

    def _browse_h_in(self) -> None:
        path = filedialog.askopenfilename(title="Choose a file to hash")
        if path:
            self.h_in.set(str(Path(path)))

    def _clear_hash_result(self) -> None:
        self.h_actual.set("")
        self.h_result.configure(text="", style="ResultNeutral.TLabel")

    def _copy_hash(self) -> None:
        value = self.h_actual.get()
        if value:
            self.clipboard_clear()
            self.clipboard_append(value)
            self.status_var.set("Hash copied to clipboard")

    def _start_hash(self) -> None:
        text = clean_path(self.h_in.get())
        src = Path(text)
        if not text or not src.is_file():
            return self._error("No file", "Choose an existing file to hash.")
        algorithm = ALGO_BY_LABEL[self.h_algo.get()]
        expected = self.h_expected.get().strip()
        if expected:
            try:
                integrity.normalize_hash(expected, algorithm)
            except integrity.InvalidHashError as exc:
                return self._error("Invalid expected hash", str(exc))

        def work(progress: cenc.ProgressCallback) -> integrity.HashComparison:
            return integrity.compare_file_hash(src, expected or None, algorithm,
                                               progress=progress)

        def ok(result: integrity.HashComparison) -> None:
            label = integrity.ALGORITHMS[result.algorithm]
            self.h_actual.set(result.actual)
            if not result.compared:
                self.h_result.configure(text=f"{label} computed.", style="ResultNeutral.TLabel")
                self._log(f"{label} of '{src.name}': {result.actual}", "ok")
                self.status_var.set("Hash computed")
            elif result.match:
                self.h_result.configure(
                    text="MATCH - the file is identical to the expected hash.",
                    style="ResultGood.TLabel")
                self._log(f"'{src.name}' matches the expected {label} hash.", "ok")
                self.status_var.set("Hash matches")
            else:
                self.h_result.configure(
                    text="MISMATCH - the file is NOT identical to the expected hash. "
                         "It was altered, corrupted, or is a different file.",
                    style="ResultBad.TLabel")
                self._log(f"'{src.name}' does NOT match the expected {label} hash "
                          f"(expected {result.expected}, got {result.actual}).", "err")
                self.status_var.set("Hash mismatch")

        self._clear_hash_result()
        self._run_task("Hashing", work, ok)

    # -- Baseline tab ---------------------------------------------------- #

    def _build_baseline_tab(self) -> None:
        f = self._tab("Baseline")
        self.b_target = tk.StringVar()
        self.b_manifest = tk.StringVar()
        self.b_algo = tk.StringVar(value=integrity.ALGORITHMS[integrity.DEFAULT_ALGORITHM])
        self.b_protect = tk.BooleanVar(value=True)
        self.b_pw = tk.StringVar()
        self.b_pw2 = tk.StringVar()

        ttk.Label(f, text="File or folder").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.b_target).grid(row=0, column=1, sticky="ew", padx=8)
        pick = ttk.Frame(f)
        pick.grid(row=0, column=2)
        ttk.Button(pick, text="File...", command=self._browse_b_file).pack(side="left")
        ttk.Button(pick, text="Folder...", command=self._browse_b_folder).pack(
            side="left", padx=(4, 0))

        self._path_row(f, 1, "Baseline file", self.b_manifest, self._browse_b_manifest)

        ttk.Label(f, text="Algorithm").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Combobox(f, textvariable=self.b_algo, values=ALGO_LABELS, state="readonly",
                     width=16).grid(row=2, column=1, sticky="w", padx=8)

        ttk.Checkbutton(
            f, variable=self.b_protect,
            text="Password-protect the baseline (so edits to the baseline itself are detected)",
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(6, 0))
        pw = self._password_row(f, 4, "Password", self.b_pw)
        pw2 = self._password_row(f, 5, "Confirm (when creating)", self.b_pw2)
        self._show_toggle(f, 4, [pw, pw2])

        ttk.Label(
            f, style="Sub.TLabel", wraplength=680,
            text="Create records the current state of the file/folder. Check compares it with "
                 "a saved baseline and lists modified, missing and new files; leave the "
                 "file/folder blank to use the location stored in the baseline.",
        ).grid(row=6, column=0, columnspan=3, sticky="w", pady=(6, 0))

        buttons = ttk.Frame(f)
        buttons.grid(row=7, column=0, columnspan=3, sticky="e", pady=(10, 0))
        for text, command in (("Create baseline", self._start_baseline_create),
                              ("Check against baseline", self._start_baseline_check)):
            btn = ttk.Button(buttons, text=text, style="Action.TButton", command=command)
            btn.pack(side="left", padx=(8, 0))
            self._action_buttons.append(btn)

        self.b_summary = ttk.Label(f, text="", style="ResultNeutral.TLabel", wraplength=680)
        self.b_summary.grid(row=8, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.b_note = ttk.Label(f, text="", style="Sub.TLabel", wraplength=680)
        self.b_note.grid(row=9, column=0, columnspan=3, sticky="w")

        tree_frame = ttk.Frame(f)
        tree_frame.grid(row=10, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
        f.rowconfigure(10, weight=1)
        self.b_tree = ttk.Treeview(tree_frame, columns=("status", "path", "detail"),
                                   show="headings", height=7)
        for col, title, width in (("status", "Status", 90), ("path", "File", 300),
                                  ("detail", "Detail", 300)):
            self.b_tree.heading(col, text=title)
            self.b_tree.column(col, width=width, anchor="w")
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.b_tree.yview)
        self.b_tree.configure(yscrollcommand=scroll.set)
        self.b_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        for status, color in STATUS_COLORS.items():
            self.b_tree.tag_configure(status, foreground=color)

        self.b_target.trace_add("write", lambda *_: self._autofill_output(
            "b_manifest", self.b_target, lambda p: str(integrity.default_baseline_path(p))))

    def _browse_b_file(self) -> None:
        path = filedialog.askopenfilename(title="Choose a file")
        if path:
            self.b_target.set(str(Path(path)))

    def _browse_b_folder(self) -> None:
        path = filedialog.askdirectory(title="Choose a folder")
        if path:
            self.b_target.set(str(Path(path)))

    def _browse_b_manifest(self) -> None:
        initial = Path(clean_path(self.b_manifest.get()) or "")
        path = filedialog.asksaveasfilename(
            title="Baseline file (choose an existing one to check, or a new name to create)",
            confirmoverwrite=False, defaultextension=".json",
            initialfile=initial.name, initialdir=str(initial.parent) if initial.name else None,
            filetypes=[("Baseline files", "*.json"), ("All files", "*.*")])
        if path:
            self.b_manifest.set(str(Path(path)))

    def _clear_baseline_results(self) -> None:
        self.b_tree.delete(*self.b_tree.get_children())
        self.b_summary.configure(text="", style="ResultNeutral.TLabel")
        self.b_note.configure(text="", style="Sub.TLabel")

    def _start_baseline_create(self) -> None:
        target_text = clean_path(self.b_target.get())
        target = Path(target_text)
        if not target_text or not target.exists():
            return self._error("No target", "Choose an existing file or folder to record.")
        manifest_text = clean_path(self.b_manifest.get())
        manifest = Path(manifest_text) if manifest_text else integrity.default_baseline_path(target)
        algorithm = ALGO_BY_LABEL[self.b_algo.get()]

        password: Optional[str] = None
        if self.b_protect.get():
            password = self.b_pw.get()
            if not password:
                return self._error("No password", "Enter a password, or untick password protection.")
            if password != self.b_pw2.get():
                return self._error("Passwords differ", "The two passwords do not match.")
        if manifest.resolve() == target.resolve():
            return self._error("Same file", "The baseline file must be different from the target.")

        overwrite = False
        if manifest.exists():
            if not messagebox.askyesno(
                    "File exists", f"'{manifest.name}' already exists. Replace it?"):
                return
            overwrite = True

        def work(progress: cenc.ProgressCallback):
            return integrity.create_baseline(target, manifest, algorithm=algorithm,
                                             password=password, overwrite=overwrite,
                                             progress=progress)

        def ok(result) -> None:
            baseline, path = result
            kind = "folder" if baseline.is_dir else "file"
            protection = "password-protected" if baseline.protected else "not password-protected"
            self.b_summary.configure(
                text=f"Baseline recorded: {len(baseline.files)} file(s), "
                     f"{human_size(baseline.total_size)} ({protection}).",
                style="ResultGood.TLabel")
            self.b_note.configure(
                text=f"Saved to {path}",
                style="Sub.TLabel")
            self._log(f"Recorded {len(baseline.files)} file(s) from {kind} '{target.name}' "
                      f"-> '{path}' ({protection}).", "ok")
            if not baseline.protected:
                self._log("This baseline is not password-protected; someone able to change the "
                          "files could also change it.", "warn")
            self.status_var.set("Baseline recorded")
            self.b_pw.set("")
            self.b_pw2.set("")

        self._clear_baseline_results()
        self._run_task("Baseline creation", work, ok)

    def _start_baseline_check(self) -> None:
        manifest_text = clean_path(self.b_manifest.get())
        manifest = Path(manifest_text)
        if not manifest_text or not manifest.is_file():
            return self._error("No baseline", "Choose an existing baseline file to check against.")
        try:
            baseline = integrity.read_baseline(manifest)
        except (cenc.CencError, OSError) as exc:
            self._log(f"Cannot use baseline: {exc}", "err")
            return self._error("Invalid baseline", str(exc))

        target_text = clean_path(self.b_target.get())
        target = Path(target_text) if target_text else None
        if target is not None and not target.exists():
            return self._error("Target not found", f"'{target}' does not exist.")
        password = self.b_pw.get() or None
        if baseline.protected and not password:
            return self._error("Password needed",
                               "This baseline is password-protected. Enter its password.")

        def work(progress: cenc.ProgressCallback) -> integrity.CheckReport:
            return integrity.check_baseline(manifest, target,
                                            password=password if baseline.protected else None,
                                            progress=progress)

        def ok(report: integrity.CheckReport) -> None:
            self._show_report(report)
            self.b_pw.set("")

        self._clear_baseline_results()
        self._run_task("Baseline check", work, ok)

    def _show_report(self, report: integrity.CheckReport) -> None:
        ordered = sorted(report.results, key=lambda r: (STATUS_ORDER[r.status], r.path))
        for r in ordered:
            self.b_tree.insert("", "end", values=(r.status.upper(), r.path, r.detail),
                               tags=(r.status,))

        n = len(report.results)
        if report.ok:
            self.b_summary.configure(
                text=f"No changes detected: all {n} file(s) match the baseline.",
                style="ResultGood.TLabel")
            self.status_var.set("No changes")
            self._log(f"Baseline check passed: all {n} file(s) unchanged.", "ok")
        else:
            parts = [f"{report.count(s)} {label}" for s, label in
                     ((integrity.MODIFIED, "modified"), (integrity.MISSING, "missing"),
                      (integrity.NEW, "new"), (integrity.ERROR, "unreadable"))
                     if report.count(s)]
            self.b_summary.configure(text="CHANGES DETECTED: " + ", ".join(parts) + ".",
                                     style="ResultBad.TLabel")
            self.status_var.set("Changes detected")
            self._log("Baseline check found changes: " + ", ".join(parts) + ".", "err")
            for r in report.problems[:20]:
                self._log(f"  {r.status.upper()}: {r.path}" + (f" ({r.detail})" if r.detail else ""),
                          "warn")
            if len(report.problems) > 20:
                self._log(f"  ... and {len(report.problems) - 20} more.", "warn")

        if report.authenticated:
            self.b_note.configure(
                text="Baseline authenticity verified: the password was correct and the "
                     "baseline has not been altered.", style="Good.TLabel")
        else:
            self.b_note.configure(
                text="This baseline is not password-protected, so it cannot prove it wasn't "
                     "edited along with the files. Re-create it with a password for "
                     "tamper-evidence.", style="Warn.TLabel")

    # ------------------------------------------------------------------ #
    # Helpers shared by the tabs
    # ------------------------------------------------------------------ #

    def _default_kdf_label(self) -> str:
        return SUITES_LABEL.get(cenc.default_version(), "AES-256-GCM")

    def _autofill_output(self, out_name: str, in_var: tk.StringVar,
                         make: Callable[[Path], str]) -> None:
        """Suggest an output path, unless the user has typed their own."""
        out_var: tk.StringVar = getattr(self, out_name)
        current = out_var.get()
        if current and current != self._autofill.get(out_name):
            return
        text = clean_path(in_var.get())
        suggestion = make(Path(text)) if text else ""
        self._autofill[out_name] = suggestion
        out_var.set(suggestion)

    def _log(self, message: str, tag: str = "info") -> None:
        stamp = time.strftime("%H:%M:%S")
        self.log.configure(state="normal")
        self.log.insert("end", f"[{stamp}] {message}\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_busy(self, busy: bool) -> None:
        for btn in self._action_buttons:
            btn.configure(state="disabled" if busy else "normal")
        self.cancel_btn.configure(state="normal" if busy else "disabled")
        if hasattr(self, "c_upload_img_btn"):
            sub_state = "disabled" if busy else "normal"
            self.c_upload_img_btn.configure(state=sub_state)
            self.c_upload_vid_btn.configure(state=sub_state)
            self.c_upload_pdf_btn.configure(state=sub_state)
            self.c_clear_btn.configure(state=sub_state)
            self.c_remove_img_btn.configure(
                state="normal" if (not busy and self._c_media_path is not None) else "disabled"
            )
        if hasattr(self, "v_tree"):
            self._update_vault_buttons()
        self._update_enc_again_btn()
        if not busy:
            self.bar.stop()
            self.bar.configure(mode="determinate")

    def _request_cancel(self) -> None:
        if self._worker and self._worker.is_alive():
            self._cancel.set()
            self.status_var.set("Cancelling...")
            self.cancel_btn.configure(state="disabled")

    @property
    def busy(self) -> bool:
        return self._worker is not None and self._worker.is_alive()

    # ------------------------------------------------------------------ #
    # Worker plumbing
    # ------------------------------------------------------------------ #

    def _run_task(self, name: str, work: Callable[[cenc.ProgressCallback], object],
                  on_success: Callable[[object], None],
                  on_cancel: Optional[Callable[[], str]] = None) -> None:
        if self.busy:
            return
        self._cancel.clear()
        self._last_phase = ""
        self._task_name = name
        self._on_success = on_success
        self._on_cancel = on_cancel
        self._set_busy(True)
        self.status_var.set(f"{name}...")
        self.bar.configure(value=0)
        self._log(f"{name} started.", "info")

        def progress(phase: str, done: int, total: int) -> None:
            if self._cancel.is_set():
                raise cenc.OperationCancelled("operation cancelled")
            self._queue.put(("progress", phase, done, total))

        def target() -> None:
            try:
                result = work(progress)
            except BaseException as exc:  # noqa: BLE001 - reported on the UI thread
                self._queue.put(("error", exc))
            else:
                self._queue.put(("done", result))

        self._worker = threading.Thread(target=target, name="cenc-worker", daemon=True)
        self._worker.start()

    def _poll(self) -> None:
        try:
            while True:
                msg = self._queue.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    self._on_progress(*msg[1:])
                elif kind == "done":
                    self._finish_ok(msg[1])
                elif kind == "error":
                    self._finish_error(msg[1])
        except queue.Empty:
            pass
        if self._closing and not self.busy:
            self.destroy()
            return
        self._poll_job = self.after(POLL_MS, self._poll)

    def destroy(self) -> None:
        if getattr(self, "_poll_job", None):
            try:
                self.after_cancel(self._poll_job)
            except tk.TclError:
                pass
            self._poll_job = None
        super().destroy()

    def _on_progress(self, phase: str, done: int, total: int) -> None:
        self._last_phase = phase
        if phase in INDETERMINATE_PHASES:
            if str(self.bar.cget("mode")) != "indeterminate":
                self.bar.configure(mode="indeterminate")
                self.bar.start(12)
            self.status_var.set(f"{phase}...")
            return
        if str(self.bar.cget("mode")) != "determinate":
            self.bar.stop()
            self.bar.configure(mode="determinate")
        if len(phase) > 52:  # long relative paths in folder operations
            phase = "..." + phase[-49:]
        pct = 100.0 if total == 0 else done * 100.0 / total
        self.bar.configure(value=pct)
        self.status_var.set(f"{phase}: {pct:.0f}%  ({human_size(done)} of {human_size(total)})")

    def _finish_ok(self, result: object) -> None:
        self._set_busy(False)
        self.bar.configure(value=100)
        self.status_var.set("Done")
        self._on_success(result)

    def _finish_error(self, exc: BaseException) -> None:
        self._set_busy(False)
        self.bar.configure(value=0)

        if isinstance(exc, cenc.OperationCancelled):
            note = self._on_cancel() if self._on_cancel else "No files were changed."
            self.status_var.set("Cancelled")
            self._log(f"{self._task_name} cancelled. {note}", "warn")
            return
        if isinstance(exc, cenc.SourceRemovalError):
            self.status_var.set("Encrypted, but the original was not deleted")
            self._log(str(exc), "warn")
            messagebox.showwarning(
                "Original not deleted",
                f"{exc}\n\nThe encrypted file is safe. Close any program using the "
                "original and delete it manually.")
            return

        self.status_var.set("Failed")
        if isinstance(exc, cenc.AuthenticationError):
            title = "Authentication failed"
        elif isinstance(exc, integrity.BaselineAuthError):
            title = "Baseline authentication failed"
        elif isinstance(exc, (cenc.InvalidFormatError, integrity.InvalidBaselineError)):
            title = "Invalid file"
        elif isinstance(exc, integrity.InvalidHashError):
            title = "Invalid hash"
        elif isinstance(exc, (cenc.CencError, OSError)):
            title = "Error"
        else:
            title = "Unexpected error"
            exc = RuntimeError(f"{type(exc).__name__}: {exc}")
        self._log(f"{self._task_name} failed: {exc}", "err")
        messagebox.showerror(title, str(exc))

    def _on_close(self) -> None:
        if self.busy:
            if not messagebox.askyesno(
                    "Operation in progress",
                    "An operation is still running. Cancel it and exit?"):
                return
            self._closing = True
            self._cancel.set()
            self.status_var.set("Cancelling...")
            return
        self.destroy()

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #

    def _error(self, title: str, message: str) -> None:
        self.status_var.set("Idle")
        messagebox.showerror(title, message)

    def _start_encrypt(self) -> None:
        src = Path(clean_path(self.enc_in.get()))
        layers = self._read_layers(self.enc_layers)
        out_text = clean_path(self.enc_out.get())
        dst = (Path(out_text) if out_text
               else src.with_name(src.name + (cenc.ENC_SUFFIX * layers)))
        password, confirm = self.enc_pw.get(), self.enc_pw2.get()
        delete = self.enc_delete.get()

        if not clean_path(self.enc_in.get()) or not src.is_file():
            return self._error("No file", "Choose an existing file to encrypt.")
        if not password:
            return self._error("No password", "Enter a password.")
        if password != confirm:
            return self._error("Passwords differ", "The two passwords do not match.")
        if src.resolve() == dst.resolve():
            return self._error("Same file", "The output must be a different file.")

        src_was_encrypted = cenc.is_cenc_file(src)
        prior_layers = max(1, cenc.count_enc_suffixes(src)) if src_was_encrypted else 0
        total_layers = prior_layers + layers

        overwrite = True

        version = (cenc.VERSION_PBKDF2 if self.enc_kdf.get() == KDF_PBKDF2
                   else cenc.VERSION_ARGON2ID)

        def work(progress: cenc.ProgressCallback) -> Path:
            return cenc.encrypt_file_layers(
                src, dst, password, layers=layers, version=version,
                overwrite=overwrite, remove_source=delete, progress=progress,
            )

        def ok(_result: object) -> None:
            layer_desc = f" (now {total_layers} encryption layers)" if total_layers > 1 else ""
            if delete:
                msg = f"Encrypted '{src.name}' -> '{dst}'{layer_desc}. Original wiped and deleted."
            else:
                msg = f"Encrypted '{src.name}' -> '{dst}'{layer_desc}. Original kept."
            self._log(msg, "ok")
            self.status_var.set(f"Encrypted{layer_desc}")
            self.enc_pw.set("")
            self.enc_pw2.set("")
            self.enc_layers.set(1)
            self._last_encrypted_output = dst
            self._update_enc_again_btn()
            self.dec_in.set(str(dst))  # handy: ready to decrypt/test
            self._refresh_vault()

        def cancelled() -> str:
            if self._last_phase in ("Verifying", "Deleting original"):
                return f"The original was kept; the encrypted file '{dst}' was left in place."
            return "No files were changed."

        self._run_task("Encryption", work, ok, cancelled)

    def _start_decrypt(self) -> None:
        src_text = clean_path(self.dec_in.get())
        src = Path(src_text)
        unwrap_all = self.dec_unwrap_all.get()
        delete_src = self.dec_delete.get()
        out_text = clean_path(self.dec_out.get())
        dst = (Path(out_text) if out_text
               else (cenc.strip_enc_suffixes(src) if unwrap_all else cenc._default_decrypt_output(src)))
        password = self.dec_pw.get()

        if not src_text or not src.is_file():
            return self._error("No file", "Choose an existing .enc file to decrypt.")
        try:
            cenc.read_container_info(src)  # reject non-CENC files before doing any work
        except (cenc.CencError, OSError) as exc:
            self._log(f"Decryption refused: {exc}", "err")
            return self._error("Invalid file", str(exc))
        if not password:
            return self._error("No password", "Enter the password.")
        if src.resolve() == dst.resolve():
            return self._error("Same file", "The output must be a different file.")

        overwrite = True

        def work(progress: cenc.ProgressCallback) -> tuple[Path, int, bool]:
            return cenc.decrypt_file_layers(
                src, dst, password, unwrap_all=unwrap_all,
                overwrite=overwrite, remove_source=delete_src, progress=progress,
            )

        def ok(result: object) -> None:
            final_dst, layers_done, still_encrypted = result  # type: ignore[misc]
            self.dec_pw.set("")
            extra = " Encrypted file removed." if delete_src else ""
            if still_encrypted:
                self._log(
                    f"Decrypted {layers_done} layer(s) '{src.name}' -> '{final_dst.name}'.{extra} "
                    "Inner encryption layer detected — enter the next password and click Decrypt.",
                    "ok",
                )
                self.status_var.set(
                    f"Unwrapped to '{final_dst.name}' (still encrypted — enter next password)"
                )
                # Automatically advance to the unwrapped inner .enc file so the user can decrypt the next layer!
                self.dec_in.set(str(final_dst))
            else:
                layer_note = f" ({layers_done} layers unwrapped)" if layers_done > 1 else ""
                self._log(f"Decrypted '{src.name}' -> '{final_dst}'{layer_note}.{extra}", "ok")
                self.status_var.set(f"Decrypted{layer_note}")
            self._refresh_vault()

        self._run_task("Decryption", work, ok)

    def _start_verify(self) -> None:
        src_text = clean_path(self.ins_in.get())
        src = Path(src_text)
        password = self.ins_pw.get()

        if not src_text or not src.is_file():
            return self._error("No file", "Choose an existing .enc file to verify.")
        try:
            cenc.read_container_info(src)
        except (cenc.CencError, OSError) as exc:
            return self._error("Invalid file", str(exc))
        if not password:
            return self._error("No password", "Enter the password.")

        def work(progress: cenc.ProgressCallback) -> cenc.Header:
            return cenc.verify_file(src, password, progress=progress)

        def ok(_result: object) -> None:
            self._log(f"'{src.name}' is authentic and the password is correct.", "ok")
            self.status_var.set("Verified")
            self.ins_pw.set("")
            messagebox.showinfo("Verified", "The file is authentic and the password is correct.")

        self._run_task("Verification", work, ok)


SUITES_LABEL = {
    cenc.VERSION_ARGON2ID: "Argon2id + AES-256-GCM",
    cenc.VERSION_PBKDF2: "PBKDF2-HMAC-SHA256 + AES-256-GCM",
}


def main() -> int:
    if sys.platform == "win32":  # crisp text on high-DPI displays
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001 - purely cosmetic
            pass
    App().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
