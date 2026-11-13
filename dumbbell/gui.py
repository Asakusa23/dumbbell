from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, font as tkfont, messagebox, ttk

from . import __version__
from .icon import ASCII_LOGO, asset_path
from .models import Finding, ScanResult, Severity
from .report import to_json, to_markdown, to_sarif
from .rules import RULES
from .scanner import scan_path

BG = "#000000"
PANEL = "#0b0b0b"
FG = "#f2f2f2"
DIM = "#8a8a8a"
FAINT = "#5a5a5a"
BORDER = "#242424"
SEL_BG = "#f2f2f2"
SEL_FG = "#000000"
CODE_BG = "#121212"

SEV_COLORS = {
    Severity.CRITICAL: "#ffffff",
    Severity.HIGH: "#e6e6e6",
    Severity.MEDIUM: "#c2c2c2",
    Severity.LOW: "#969696",
    Severity.INFO: "#6e6e6e",
}


class LogoCanvas(tk.Canvas):
    def __init__(self, parent, font_factory, width=760, height=176):
        super().__init__(
            parent,
            width=width,
            height=height,
            bg=BG,
            highlightthickness=0,
            bd=0,
        )
        self._font = font_factory
        self._width = width
        self._height = height
        self._logo_image = self._load_logo()
        self._layout_after = None
        self.bind("<Configure>", self._on_configure)
        self._layout()

    def _on_configure(self, event):
        width = max(1, event.width)
        height = max(1, event.height)
        if (width, height) == (self._width, self._height):
            return
        self._width = width
        self._height = height
        if self._layout_after is not None:
            self.after_cancel(self._layout_after)
        self._layout_after = self.after_idle(self._layout)

    def stop(self):
        if self._layout_after is not None:
            try:
                self.after_cancel(self._layout_after)
            except tk.TclError:
                pass
            self._layout_after = None

    def _load_logo(self):
        path = asset_path("logo_header.png")
        if not path.is_file():
            return None
        try:
            return tk.PhotoImage(file=str(path))
        except tk.TclError:
            return None

    def _layout(self):
        self._layout_after = None
        self.delete("all")
        width = self._width
        height = self._height
        if width < 80 or height < 60:
            return
        center = height / 2
        if self._logo_image is not None:
            logo_width = self._logo_image.width()
            left = 18
            self.create_image(left + logo_width / 2, center, image=self._logo_image, anchor="center")
            text_x = left + logo_width + 26
        else:
            self._text(150, center, ASCII_LOGO, self._font(9), FG, anchor="center", justify="left")
            text_x = 310
        self._text(text_x, center - 12, "STATIC SECURITY AUDIT", self._font(10, True), DIM, anchor="w")
        self._text(
            text_x,
            center + 10,
            "lift your code. drop the vulnerabilities.",
            self._font(9),
            FAINT,
            anchor="w",
        )
        if width >= 720:
            right = width - 18
            self._text(right, center - 30, "QUICK KEYS", self._font(8, True), DIM, anchor="e")
            for offset, line in enumerate(("CTRL+O   OPEN TARGET", "F5       RESCAN", "ESC      STOP")):
                self._text(right, center - 12 + offset * 16, line, self._font(8), FAINT, anchor="e")

    def _text(self, x, y, text, font, fill, anchor="nw", justify="left"):
        for dx, dy in ((-1, 0), (1, 0), (0, -1), (0, 1), (2, 2)):
            self.create_text(
                x + dx,
                y + dy,
                text=text,
                font=font,
                fill="#000000",
                anchor=anchor,
                justify=justify,
            )
        self.create_text(
            x,
            y,
            text=text,
            font=font,
            fill=fill,
            anchor=anchor,
            justify=justify,
        )


class ToggleButton(tk.Label):
    def __init__(self, parent, label, value, on_change, font, **kwargs):
        self.label = label
        self.value = value
        self.on_change = on_change
        self.var = tk.StringVar()
        super().__init__(parent, textvariable=self.var, font=font, bg=BG, fg=FG, cursor="hand2", padx=6, pady=2, **kwargs)
        self.bind("<Button-1>", self._toggle)
        self._render()

    def _render(self):
        self.var.set(f"[{'x' if self.value else ' '}] {self.label}")
        self.configure(fg=FG if self.value else FAINT)

    def _toggle(self, _event):
        self.value = not self.value
        self._render()
        self.on_change(self.value)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DUMBBELL // static security audit")
        self.configure(bg=BG)
        self.minsize(980, 680)
        self.resizable(True, True)

        families = set(tkfont.families(self))
        self.mono_family = "Courier"
        for candidate in ("Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Liberation Mono", "Courier New"):
            if candidate in families:
                self.mono_family = candidate
                break

        self.findings: list[Finding] = []
        self.result: ScanResult | None = None
        self.scanning = False
        self.cancel_event: threading.Event | None = None
        self._queue: queue.Queue | None = None
        self._iid_map: dict[str, Finding] = {}
        self._filters = {severity: True for severity in Severity.ordered()}
        self._progress_done = 0
        self._progress_total = 0

        self._configure_style()
        self._build_header()
        self._build_controls()
        self._build_main()
        self._build_log()
        self._build_status()
        self._set_icon()
        self._center()
        self._clear_details()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<Control-o>", lambda _event: self._browse())
        self.bind("<F5>", lambda _event: self._start_scan())
        self.bind("<Escape>", lambda _event: self._stop_scan())
        self.bind("<Control-e>", lambda _event: self._export())

        self._log(f"DUMBBELL v{__version__} // static security audit", "ok", stamp=False)
        self._log("ready. pick a target and press SCAN. F5 rescans, ESC stops.", stamp=False)
        self._log(f"loaded {len(RULES)} rules across {len({rule.category for rule in RULES})} categories", stamp=False)
        self._log("-" * 78, "dim", stamp=False)

    def _font(self, size: int, bold: bool = False):
        return (self.mono_family, size, "bold" if bold else "normal")

    def _configure_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Treeview",
            background=PANEL,
            fieldbackground=PANEL,
            foreground=FG,
            rowheight=23,
            font=self._font(10),
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=BG,
            foreground=DIM,
            font=self._font(9, True),
            relief="flat",
            borderwidth=0,
            padding=(6, 6),
        )
        style.map("Treeview.Heading", background=[("active", BG)])
        style.map("Treeview", background=[("selected", SEL_BG)], foreground=[("selected", SEL_FG)])
        style.configure(
            "Vertical.TScrollbar",
            background=BORDER,
            troughcolor=PANEL,
            bordercolor=PANEL,
            arrowcolor=DIM,
            lightcolor=BORDER,
            darkcolor=BORDER,
            relief="flat",
        )
        style.map("Vertical.TScrollbar", background=[("active", FAINT)])

    def _button(self, parent, text, command, primary=False):
        background = FG if primary else BG
        foreground = BG if primary else FG
        hover = "#d8d8d8" if primary else "#161616"
        button = tk.Button(
            parent,
            text=text,
            command=command,
            font=self._font(10, True),
            bg=background,
            fg=foreground,
            activebackground=hover,
            activeforeground=foreground,
            disabledforeground=FAINT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=BORDER,
            padx=12,
            pady=6,
            cursor="hand2",
        )
        button.bind("<Enter>", lambda _event: button.configure(bg=hover) if button["state"] != "disabled" else None)
        button.bind("<Leave>", lambda _event: button.configure(bg=background))
        return button

    def _divider(self, parent):
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=18)

    def _build_header(self):
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=18, pady=(14, 10))

        self.logo_canvas = LogoCanvas(header, self._font, width=760, height=176)
        self.logo_canvas.pack(side="left", fill="both", expand=True)

        stats = tk.Frame(header, bg=BG)
        stats.pack(side="right", anchor="e", padx=(18, 0))
        self.rules_var = tk.StringVar(value=f"RULES {len(RULES):02d}")
        self.risk_var = tk.StringVar(value="RISK --/100")
        tk.Label(stats, textvariable=self.rules_var, font=self._font(10, True), bg=BG, fg=DIM).pack(anchor="e")
        tk.Label(stats, textvariable=self.risk_var, font=self._font(16, True), bg=BG, fg=FG).pack(anchor="e", pady=(2, 0))
        tk.Label(stats, text="ENGINE REGEX", font=self._font(8), bg=BG, fg=FAINT).pack(anchor="e")

    def _build_controls(self):
        self._divider(self)
        controls = tk.Frame(self, bg=BG)
        controls.pack(fill="x", padx=18, pady=(10, 8))

        row1 = tk.Frame(controls, bg=BG)
        row1.pack(fill="x")
        tk.Label(row1, text="TARGET", font=self._font(9, True), bg=BG, fg=DIM).pack(side="left")
        self.path_var = tk.StringVar(value=str(Path.cwd()))
        self.path_entry = tk.Entry(
            row1,
            textvariable=self.path_var,
            font=self._font(10),
            bg=PANEL,
            fg=FG,
            insertbackground=FG,
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=FG,
        )
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(10, 8), ipady=5)
        self.path_entry.bind("<Return>", lambda _event: self._start_scan())
        self._button(row1, "BROWSE", self._browse).pack(side="left", padx=(0, 6))
        self.scan_btn = self._button(row1, "SCAN", self._start_scan, primary=True)
        self.scan_btn.pack(side="left")
        self.stop_btn = self._button(row1, "STOP", self._stop_scan)
        self.stop_btn.pack(side="left", padx=(6, 0))
        self.stop_btn.configure(state="disabled")

        row2 = tk.Frame(controls, bg=BG)
        row2.pack(fill="x", pady=(8, 0))
        tk.Label(row2, text="SEVERITY", font=self._font(9, True), bg=BG, fg=DIM).pack(side="left")
        for severity in Severity.ordered():
            toggle = ToggleButton(
                row2,
                severity.name,
                True,
                lambda value, current=severity: self._on_filter_change(current, value),
                self._font(9),
            )
            toggle.pack(side="left", padx=(8, 0))
        self.export_btn = self._button(row2, "EXPORT", self._export)
        self.export_btn.pack(side="right")

    def _build_main(self):
        paned = tk.PanedWindow(
            self,
            orient="horizontal",
            bg=BORDER,
            sashwidth=4,
            sashrelief="flat",
            bd=0,
            showhandle=False,
        )
        paned.pack(fill="both", expand=True, padx=18, pady=(4, 6))

        left = tk.Frame(paned, bg=BG)
        right = tk.Frame(paned, bg=BG)
        paned.add(left, minsize=420)
        paned.add(right, minsize=320)

        tree_frame = tk.Frame(left, bg=BG)
        tree_frame.pack(fill="both", expand=True)
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("sev", "rule", "loc", "title"),
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("sev", text="SEVERITY", anchor="w")
        self.tree.heading("rule", text="RULE", anchor="w")
        self.tree.heading("loc", text="LOCATION", anchor="w")
        self.tree.heading("title", text="TITLE", anchor="w")
        self.tree.column("sev", width=82, minwidth=70, stretch=False, anchor="w")
        self.tree.column("rule", width=92, minwidth=80, stretch=False, anchor="w")
        self.tree.column("loc", width=220, minwidth=140, stretch=False, anchor="w")
        self.tree.column("title", width=320, minwidth=160, stretch=True, anchor="w")
        self.tree.tag_configure("critical", foreground=SEV_COLORS[Severity.CRITICAL], font=self._font(10, True))
        self.tree.tag_configure("high", foreground=SEV_COLORS[Severity.HIGH])
        self.tree.tag_configure("medium", foreground=SEV_COLORS[Severity.MEDIUM])
        self.tree.tag_configure("low", foreground=SEV_COLORS[Severity.LOW])
        self.tree.tag_configure("info", foreground=SEV_COLORS[Severity.INFO])
        self.tree.tag_configure("hover", background="#1a1a1a")
        self._hover_row = ""

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda _event: self._open_selected())
        self.tree.bind("<Button-3>", self._show_menu)
        self.tree.bind("<Motion>", self._on_tree_motion)
        self.tree.bind("<Leave>", self._on_tree_leave)

        self.menu = tk.Menu(
            self,
            tearoff=0,
            bg=PANEL,
            fg=FG,
            activebackground=FG,
            activeforeground=BG,
            bd=0,
            font=self._font(9),
        )
        self.menu.add_command(label="Open file", command=self._open_selected)
        self.menu.add_command(label="Open containing folder", command=self._open_folder_selected)
        self.menu.add_separator()
        self.menu.add_command(label="Copy location", command=self._copy_location)

        detail_header = tk.Frame(right, bg=BG)
        detail_header.pack(fill="x")
        tk.Label(detail_header, text="FINDING DETAIL", font=self._font(9, True), bg=BG, fg=DIM).pack(side="left")
        self._button(detail_header, "COPY FIX", self._copy_fix).pack(side="right")
        self._button(detail_header, "COPY", self._copy_location).pack(side="right", padx=(0, 6))
        self._button(detail_header, "OPEN", self._open_selected).pack(side="right", padx=(0, 6))

        self.detail = tk.Text(
            right,
            bg=PANEL,
            fg=FG,
            font=self._font(10),
            wrap="word",
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER,
            padx=12,
            pady=10,
            state="disabled",
            cursor="arrow",
        )
        self.detail.pack(fill="both", expand=True, pady=(6, 0))
        self.detail.tag_configure("head", foreground=FG, font=self._font(11, True), spacing1=2, spacing3=2)
        self.detail.tag_configure("key", foreground=DIM, font=self._font(9, True), spacing1=8)
        self.detail.tag_configure("val", foreground=FG, font=self._font(10))
        self.detail.tag_configure("code", foreground=FG, background=CODE_BG, font=self._font(10), lmargin1=8, lmargin2=8, spacing1=2, spacing3=2)
        self.detail.tag_configure("fix", foreground=FG, background=CODE_BG, font=self._font(10), lmargin1=8, lmargin2=8, spacing1=3, spacing3=3)
        for severity, color in SEV_COLORS.items():
            self.detail.tag_configure(f"sev_{severity.name.lower()}", foreground=color, font=self._font(10, True))

    def _build_log(self):
        log_frame = tk.Frame(self, bg=BG)
        log_frame.pack(fill="x", padx=18, pady=(0, 6))
        header = tk.Frame(log_frame, bg=BG)
        header.pack(fill="x")
        tk.Label(header, text="TERMINAL", font=self._font(9, True), bg=BG, fg=DIM).pack(side="left")
        tk.Label(header, text="dumbbell@localhost", font=self._font(8), bg=BG, fg=FAINT).pack(side="right")

        self.log = tk.Text(
            log_frame,
            height=7,
            bg=PANEL,
            fg=DIM,
            font=self._font(9),
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER,
            padx=10,
            pady=6,
            state="disabled",
            cursor="arrow",
        )
        self.log.pack(fill="x")
        self.log.tag_configure("critical", foreground=SEV_COLORS[Severity.CRITICAL], font=self._font(9, True))
        self.log.tag_configure("high", foreground=SEV_COLORS[Severity.HIGH])
        self.log.tag_configure("medium", foreground=SEV_COLORS[Severity.MEDIUM])
        self.log.tag_configure("low", foreground=SEV_COLORS[Severity.LOW])
        self.log.tag_configure("info", foreground=SEV_COLORS[Severity.INFO])
        self.log.tag_configure("ok", foreground=FG)
        self.log.tag_configure("dim", foreground=DIM)

    def _build_status(self):
        status = tk.Frame(self, bg=BG)
        status.pack(fill="x", padx=18, pady=(0, 12))
        self.status_var = tk.StringVar(value="READY")
        self.progress_var = tk.StringVar(value=self._bar(0) + "   0%")
        self.summary_var = tk.StringVar(value="files 0  |  findings 0  |  crit 0  high 0  med 0  low 0")
        tk.Label(status, textvariable=self.status_var, font=self._font(9, True), bg=BG, fg=FG).pack(side="left")
        tk.Label(status, textvariable=self.progress_var, font=self._font(9), bg=BG, fg=DIM).pack(side="left", padx=(16, 0))
        tk.Label(status, textvariable=self.summary_var, font=self._font(9), bg=BG, fg=DIM).pack(side="right")

    def _set_icon(self):
        png = asset_path("icon.png")
        ico = asset_path("icon.ico")
        try:
            self._icon_image = tk.PhotoImage(file=str(png))
            self.iconphoto(True, self._icon_image)
        except tk.TclError:
            pass
        if sys.platform.startswith("win") and ico.is_file():
            try:
                self.iconbitmap(default=str(ico))
            except tk.TclError:
                pass

    def _center(self):
        self.update_idletasks()
        width, height = 1180, 820
        x = (self.winfo_screenwidth() - width) // 2
        y = (self.winfo_screenheight() - height) // 2
        self.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")

    def _bar(self, percent: int, width: int = 24) -> str:
        percent = max(0, min(100, percent))
        filled = int(width * percent / 100)
        return "[" + "█" * filled + "░" * (width - filled) + "]"

    def _log(self, text: str, tag: str = "dim", stamp: bool = True):
        prefix = f"[{time.strftime('%H:%M:%S')}] " if stamp else ""
        self.log.configure(state="normal")
        self.log.insert("end", prefix + text + "\n", tag)
        line_count = int(self.log.index("end-1c").split(".")[0])
        if line_count > 1200:
            self.log.delete("1.0", f"{line_count - 1200}.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_details(self):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", "DUMBBELL // finding detail\n", "head")
        self.detail.insert("end", "-" * 40 + "\n\n", "key")
        self.detail.insert("end", "No finding selected.\n\n", "val")
        self.detail.insert(
            "end",
            "Select a row in the findings list to inspect the rule, the matched snippet, and remediation guidance.\n\n",
            "val",
        )
        self.detail.insert("end", "TIP: double-click a row to open the file in your editor.\n", "key")
        self.detail.configure(state="disabled")

    def _show_details(self, finding: Finding):
        root = self.result.root if self.result else None
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", f"{finding.rule.id}  ", "head")
        self.detail.insert("end", f"[{finding.severity.name}]\n", f"sev_{finding.severity.name.lower()}")
        self.detail.insert("end", finding.rule.title + "\n\n", "head")
        rows = (
            ("SEVERITY", finding.severity.name),
            ("CATEGORY", finding.rule.category),
            ("CWE", finding.rule.cwe or "-"),
            ("LOCATION", finding.location(root)),
        )
        for key, value in rows:
            self.detail.insert("end", f"{key:<10}", "key")
            self.detail.insert("end", value + "\n", "val")
        self.detail.insert("end", "\nSNIPPET\n", "key")
        self.detail.insert("end", f"{finding.line:>5} | {finding.snippet}\n", "code")
        self.detail.insert("end", "\nDESCRIPTION\n", "key")
        self.detail.insert("end", finding.rule.description + "\n", "val")
        self.detail.insert("end", "\nREMEDIATION / HOW TO FIX\n", "key")
        self.detail.insert("end", finding.rule.remediation + "\n", "fix")
        self.detail.configure(state="disabled")
        self.detail.yview_moveto(0)

    def _update_counts(self):
        counts = {severity.name: 0 for severity in Severity.ordered()}
        for finding in self.findings:
            counts[finding.severity.name] += 1
        total = len(self.findings)
        visible = sum(1 for finding in self.findings if self._filters[finding.severity])
        files = self.result.files_scanned if self.result else self._progress_done
        finding_text = f"{visible}/{total}" if visible != total else str(total)
        self.summary_var.set(
            f"files {files}  |  findings {finding_text}  |  crit {counts['CRITICAL']}  "
            f"high {counts['HIGH']}  med {counts['MEDIUM']}  low {counts['LOW']}"
        )
        if self.result:
            self.risk_var.set(f"RISK {self.result.risk_score():02d}/100")
        else:
            self.risk_var.set("RISK --/100")

    def _render_tree(self):
        self._hover_row = ""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._iid_map = {}
        visible = [finding for finding in self.findings if self._filters[finding.severity]]
        visible.sort(key=lambda finding: (-finding.severity.value, finding.path, finding.line, finding.rule.id))
        root = self.result.root if self.result else None
        for index, finding in enumerate(visible):
            iid = str(index)
            self._iid_map[iid] = finding
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    finding.severity.name,
                    finding.rule.id,
                    finding.location(root),
                    finding.rule.title,
                ),
                tags=(finding.severity.name.lower(),),
            )
        self._update_counts()

    def _on_filter_change(self, severity: Severity, value: bool):
        self._filters[severity] = value
        self._render_tree()
        self._log(f"[filter] {severity.name.lower()} {'shown' if value else 'hidden'}", "dim")

    def _on_tree_motion(self, event):
        row = self.tree.identify_row(event.y)
        if row != self._hover_row:
            self._set_hover_row(row)

    def _on_tree_leave(self, _event):
        self._set_hover_row("")

    def _set_hover_row(self, row: str):
        if self._hover_row:
            try:
                tags = tuple(tag for tag in self.tree.item(self._hover_row, "tags") if tag != "hover")
                self.tree.item(self._hover_row, tags=tags)
            except tk.TclError:
                pass
        self._hover_row = row
        if row and row not in self.tree.selection():
            try:
                tags = self.tree.item(row, "tags")
                if "hover" not in tags:
                    self.tree.item(row, tags=tuple(tags) + ("hover",))
            except tk.TclError:
                pass

    def _on_select(self, _event=None):
        self._set_hover_row("")
        selection = self.tree.selection()
        if not selection:
            return
        finding = self._iid_map.get(selection[0])
        if finding:
            self._show_details(finding)

    def _browse(self):
        initial = self.path_var.get().strip() or str(Path.cwd())
        selected = filedialog.askdirectory(initialdir=initial, title="Select target directory")
        if selected:
            self.path_var.set(selected)

    def _start_scan(self):
        if self.scanning:
            return
        target_text = self.path_var.get().strip()
        if not target_text:
            messagebox.showwarning("DUMBBELL", "Choose a target file or directory.")
            return
        target = Path(target_text).expanduser()
        if not target.exists():
            messagebox.showerror("DUMBBELL", f"Target not found:\n{target}")
            return

        self.scanning = True
        self.cancel_event = threading.Event()
        self.findings = []
        self.result = None
        self._iid_map = {}
        self._progress_done = 0
        self._progress_total = 0
        self._render_tree()
        self._clear_details()
        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.export_btn.configure(state="disabled")
        self.status_var.set("SCANNING")
        self.progress_var.set(self._bar(0) + "   0%")
        self._log(f"$ dumbbell scan {target}", "ok")
        ignore_file = (target if target.is_dir() else target.parent) / ".dumbbellignore"
        self._log(f"[*] rules={len(RULES)}  ignore={'on' if ignore_file.is_file() else 'off'}", "dim")

        self._queue = queue.Queue()
        worker = threading.Thread(target=self._scan_worker, args=(str(target),), daemon=True)
        worker.start()
        self.after(60, self._poll_queue)

    def _scan_worker(self, target: str):
        try:
            result = scan_path(
                target,
                on_finding=lambda finding: self._queue.put(("finding", finding)),
                on_progress=lambda done, total, path: self._queue.put(("progress", done, total, path)),
                cancel_event=self.cancel_event,
            )
            self._queue.put(("done", result))
        except Exception as exc:
            self._queue.put(("error", exc))

    def _poll_queue(self):
        if self._queue is None:
            return
        try:
            while True:
                message = self._queue.get_nowait()
                kind = message[0]
                if kind == "finding":
                    self._handle_finding(message[1])
                elif kind == "progress":
                    self._handle_progress(message[1], message[2], message[3])
                elif kind == "done":
                    self._handle_done(message[1])
                elif kind == "error":
                    self._handle_error(message[1])
        except queue.Empty:
            pass
        if self.scanning:
            self.after(60, self._poll_queue)

    def _handle_finding(self, finding: Finding):
        self.findings.append(finding)
        if self._filters[finding.severity]:
            iid = str(len(self._iid_map))
            self._iid_map[iid] = finding
            root = self.result.root if self.result else None
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(finding.severity.name, finding.rule.id, finding.location(root), finding.rule.title),
                tags=(finding.severity.name.lower(),),
            )
        self._log(
            f"[{finding.severity.name}] {finding.rule.id}  {finding.location(self.result.root if self.result else None)}",
            finding.severity.name.lower(),
        )
        self._update_counts()

    def _handle_progress(self, done: int, total: int, path: str):
        self._progress_done = done
        self._progress_total = total
        percent = 0 if total == 0 else int(done * 100 / total)
        self.progress_var.set(f"{self._bar(percent)} {percent:3d}%  {done}/{total}")
        if path:
            self.status_var.set(f"SCANNING  {Path(path).name}")
        self._update_counts()

    def _handle_done(self, result: ScanResult):
        self.scanning = False
        self.result = result
        self.findings = result.findings
        self._finish_scan()
        self._render_tree()
        self.progress_var.set(self._bar(100) + " 100%")
        self.status_var.set("CANCELLED" if result.cancelled else "DONE")
        counts = result.severity_counts()
        self._log(
            f"[done] files={result.files_scanned}  skipped={result.files_skipped}  "
            f"findings={len(result.findings)}  time={result.elapsed:.2f}s",
            "ok",
        )
        self._log(
            f"[risk] {result.risk_score():02d}/100  "
            + "  ".join(f"{name.lower()}={value}" for name, value in counts.items()),
            "ok",
        )
        if result.findings:
            children = self.tree.get_children()
            if children:
                self.tree.selection_set(children[0])
                self.tree.focus(children[0])
                self._show_details(self._iid_map[children[0]])
        else:
            self._log("[ok] no findings for the loaded rule set", "ok")

    def _handle_error(self, exc: Exception):
        self.scanning = False
        self._finish_scan()
        self.status_var.set("ERROR")
        self._log(f"[!] scan failed: {exc}", "high")
        messagebox.showerror("DUMBBELL", f"Scan failed:\n{exc}")

    def _finish_scan(self):
        self.scanning = False
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.export_btn.configure(state="normal")

    def _stop_scan(self):
        if self.scanning and self.cancel_event is not None:
            self.cancel_event.set()
            self.stop_btn.configure(state="disabled")
            self._log("[!] cancellation requested; finishing current file", "high")

    def _open_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        finding = self._iid_map.get(selection[0])
        if finding:
            self._open_path(Path(finding.path))

    def _open_folder_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        finding = self._iid_map.get(selection[0])
        if not finding:
            return
        path = Path(finding.path)
        try:
            if sys.platform.startswith("win"):
                subprocess.Popen(["explorer", "/select,", str(path)])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path.parent)])
        except OSError as exc:
            messagebox.showerror("DUMBBELL", f"Could not open folder:\n{exc}")

    def _copy_location(self):
        selection = self.tree.selection()
        if not selection:
            return
        finding = self._iid_map.get(selection[0])
        if not finding:
            return
        location = finding.location(self.result.root if self.result else None)
        self.clipboard_clear()
        self.clipboard_append(location)
        self._log(f"[copy] {location}", "dim")

    def _copy_fix(self):
        selection = self.tree.selection()
        if not selection:
            return
        finding = self._iid_map.get(selection[0])
        if not finding:
            return
        self.clipboard_clear()
        self.clipboard_append(finding.rule.remediation)
        self._log(f"[fix] {finding.rule.id} remediation copied", "dim")

    def _open_path(self, path: Path):
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(path))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except OSError as exc:
            messagebox.showerror("DUMBBELL", f"Could not open file:\n{exc}")

    def _show_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        self.tree.focus(row)
        self._on_select()
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _export(self):
        if self.result is None and not self.findings:
            if not messagebox.askyesno("DUMBBELL", "No findings yet. Export an empty report?"):
                return
        result = self.result
        if result is None:
            result = ScanResult(
                root=str(Path(self.path_var.get()).expanduser()),
                findings=self.findings,
                files_scanned=0,
                files_skipped=0,
                bytes_scanned=0,
                elapsed=0.0,
            )
        filename = filedialog.asksaveasfilename(
            title="Export report",
            defaultextension=".json",
            initialfile="dumbbell-report.json",
            filetypes=[
                ("JSON report", "*.json"),
                ("Markdown report", "*.md"),
                ("SARIF report", "*.sarif"),
                ("All files", "*.*"),
            ],
        )
        if not filename:
            return
        path = Path(filename)
        lowered = str(path).lower()
        if lowered.endswith(".md"):
            content = to_markdown(result)
        elif lowered.endswith(".sarif") or lowered.endswith(".sarif.json"):
            content = to_sarif(result)
        else:
            content = to_json(result)
        try:
            path.write_text(content, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("DUMBBELL", f"Could not write report:\n{exc}")
            return
        self._log(f"[export] {path}", "ok")

    def _on_close(self):
        if self.scanning:
            if not messagebox.askyesno("DUMBBELL", "A scan is running. Stop it and quit?"):
                return
            if self.cancel_event is not None:
                self.cancel_event.set()
        if getattr(self, "logo_canvas", None) is not None:
            self.logo_canvas.stop()
        self.destroy()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
