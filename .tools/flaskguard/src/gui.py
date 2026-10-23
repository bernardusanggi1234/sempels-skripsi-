"""Desktop workspace for reviewing Flask injection candidates.

Run with ``python -m src.gui``. Uses only the Python standard library.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .engine.taint_engine import TaintAnalysisResult, analyze_taint_file
from flaskguard.project import ProjectResult, scan_project

COLORS = {
    'bg': '#F3F5F9', 'surface': '#FFFFFF', 'ink': '#172337',
    'muted': '#6B7890', 'line': '#E3E8F0', 'accent': '#5746D9',
    'accent_hover': '#4535BC', 'sidebar': '#121D31', 'nav': '#283451',
    'red': '#BD4056', 'amber': '#A56A19', 'green': '#197760',
}
STATUS_LABELS = {'vulnerable': 'Kandidat', 'needs_review': 'Perlu tinjau', 'sanitized': 'Alur dibatasi'}
FILTERS = {'Semua status': None, 'Kandidat': 'vulnerable', 'Perlu tinjau': 'needs_review', 'Alur dibatasi': 'sanitized'}
STEP_LABELS = {'source': 'SUMBER INPUT', 'assignment': 'PENUGASAN', 'sanitizer': 'PEMBATASAN INPUT', 'sink': 'OPERASI SENSITIF'}


class ScannerApp(tk.Tk):
    def __init__(self) -> None:
        if os.name == 'nt':
            # Use physical screen coordinates on scaled Windows displays.
            # This also keeps text crisp and screenshot bounds accurate.
            import ctypes
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except (AttributeError, OSError):
                ctypes.windll.user32.SetProcessDPIAware()
        super().__init__()
        self.title('FlaskGuard | Analisis Keamanan Kode')
        width = min(1380, self.winfo_screenwidth() - 60)
        height = min(880, self.winfo_screenheight() - 100)
        self.geometry(f'{width}x{height}+20+20')
        self.minsize(1040, 650)
        self.configure(bg=COLORS['bg'])
        self.result: TaintAnalysisResult | None = None
        self.path = tk.StringVar()
        self.search = tk.StringVar()
        self.filter = tk.StringVar(value='Semua status')
        self.status = tk.StringVar(value='Siap memindai file atau folder proyek Python.')
        self.file_filter = tk.StringVar(value='Semua file')
        self._busy = False
        self._messages: queue.Queue = queue.Queue()
        self._rows = {}
        self._current_view = 'analysis'
        self._configure_styles()
        self._build()
        self.search.trace_add('write', lambda *_: self._filter_findings())
        self.filter.trace_add('write', lambda *_: self._filter_findings())
        self.file_filter.trace_add('write', lambda *_: self._filter_findings())
        self.bind('<Control-o>', lambda _: self._choose_file())
        self.bind('<Control-s>', lambda _: self._save_report())
        self.bind('<F5>', lambda _: self._scan())
        self.bind('<Configure>', self._resize_layout)
        self._compact = None
        self.after_idle(self._resize_layout)
        self.after(80, self._poll_scan)

    def _configure_styles(self):
        self.option_add('*Font', ('Segoe UI', 10))
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TEntry', padding=9, bordercolor=COLORS['line'], lightcolor=COLORS['line'], fieldbackground='white')
        style.map('TEntry', bordercolor=[('focus', COLORS['accent'])])
        style.configure('TCombobox', padding=8, fieldbackground='white', background='white', bordercolor=COLORS['line'], arrowsize=13)
        style.map('TCombobox', fieldbackground=[('readonly', 'white')], selectbackground=[('readonly', 'white')], selectforeground=[('readonly', COLORS['ink'])])
        style.configure('Treeview', font=('Segoe UI', 10), rowheight=42, background='white', fieldbackground='white', foreground=COLORS['ink'], borderwidth=0)
        style.configure('Treeview.Heading', font=('Segoe UI', 9, 'bold'), background='#F7F9FC', foreground=COLORS['muted'], relief='flat', padding=(10, 12), borderwidth=0)
        style.map('Treeview', background=[('selected', '#EEEBFF')], foreground=[('selected', '#4434B2')])
        style.map('Treeview.Heading', background=[('active', '#EDF0F7')])
        style.configure('Vertical.TScrollbar', background='#D3DAE7', troughcolor='white', borderwidth=0, arrowsize=11)
        style.configure('Horizontal.TScrollbar', background='#D3DAE7', troughcolor='white', borderwidth=0, arrowsize=11)
        style.configure('Scan.Horizontal.TProgressbar', background=COLORS['accent'], troughcolor='#E8E5FA', borderwidth=0, thickness=3)

    def _label(self, parent, text='', size=10, color=None, bold=False, bg=None, **kwargs):
        return tk.Label(parent, text=text, font=('Segoe UI', size, 'bold' if bold else 'normal'), fg=color or COLORS['ink'], bg=bg or parent.cget('bg'), **kwargs)

    def _button(self, parent, text, command, primary=False):
        return tk.Button(parent, text=text, command=command, font=('Segoe UI', 10, 'bold'),
                         bg=COLORS['accent'] if primary else 'white', fg='white' if primary else COLORS['ink'],
                         activebackground=COLORS['accent_hover'] if primary else '#EEF0F6',
                         activeforeground='white' if primary else COLORS['ink'],
                         disabledforeground='#A4AEC0', relief='flat', bd=0,
                         padx=16, pady=10, cursor='hand2', takefocus=True)

    def _card(self, parent, **kwargs):
        return tk.Frame(parent, bg='white', highlightbackground=COLORS['line'], highlightthickness=1, **kwargs)

    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        sidebar = tk.Frame(self, bg=COLORS['sidebar'], width=206)
        sidebar.grid(row=0, column=0, sticky='nsew')
        sidebar.pack_propagate(False)
        self._build_sidebar(sidebar)
        main = tk.Frame(self, bg=COLORS['bg'])
        main.grid(row=0, column=1, sticky='nsew', padx=22, pady=(16, 10))
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(4, weight=1)

        header = tk.Frame(main, bg=COLORS['bg'])
        header.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        self._label(header, 'WORKSPACE  /  KEAMANAN APLIKASI', 9, COLORS['muted'], True).pack(anchor='w')
        title_row = tk.Frame(header, bg=COLORS['bg'])
        title_row.pack(fill='x', pady=(5, 3))
        self.main_title = self._label(title_row, 'Analisis kode Flask', 22, bold=True)
        self.main_title.pack(side='left')
        self.export_button = self._button(title_row, 'Ekspor laporan', self._save_report)
        self.export_button.pack(side='right')
        self.export_button.configure(state='disabled')
        self.subtitle = self._label(header, 'Telusuri input, pahami risikonya, dan tinjau setiap temuan.', 9, COLORS['muted'])
        self.subtitle.pack(anchor='w')

        target = self._card(main)
        target.grid(row=1, column=0, sticky='ew', pady=(0, 10))
        target.grid_columnconfigure(0, weight=1)
        self._label(target, 'FILE / FOLDER PROYEK', 8, COLORS['muted'], True).grid(row=0, column=0, sticky='w', padx=16, pady=(8, 3))
        self.path_entry = ttk.Entry(target, textvariable=self.path)
        self.path_entry.grid(row=1, column=0, sticky='ew', padx=(16, 8), pady=(0, 14))
        self.path_entry.bind('<Return>', lambda _: self._scan())
        self.choose_button = self._button(target, 'Pilih file', self._choose_file)
        self.choose_button.grid(row=1, column=1, padx=(0, 8), pady=(0, 14))
        self.scan_button = self._button(target, 'Mulai analisis  →', self._scan, primary=True)
        self.folder_button = self._button(target, 'Pilih folder', self._choose_folder)
        self.folder_button.grid(row=1, column=2, padx=(0, 8), pady=(0, 14))
        self.scan_button.grid(row=1, column=3, padx=(0, 16), pady=(0, 14))
        progress_track = tk.Frame(target, bg='#E8E5FA', height=3)
        progress_track.grid(row=2, column=0, columnspan=4, sticky='ew')
        progress_track.pack_propagate(False)
        self.progress = ttk.Progressbar(progress_track, mode='indeterminate', style='Scan.Horizontal.TProgressbar')
        self.progress.pack(fill='both', expand=True)

        metrics = tk.Frame(main, bg=COLORS['bg'])
        metrics.grid(row=2, column=0, sticky='ew', pady=(0, 10))
        self.metric_values = []
        self.metric_captions = []
        for i, (title, caption, color) in enumerate([
            ('Kandidat injeksi', 'Input menuju sink', COLORS['red']),
            ('Perlu ditinjau', 'Konteks belum pasti', COLORS['amber']),
            ('Alur dibatasi', 'Binding / konversi', COLORS['green']),
            ('Entry point', 'Fungsi yang dikenali', COLORS['accent']),
        ]):
            metrics.grid_columnconfigure(i, weight=1, uniform='cards')
            card = self._card(metrics)
            card.grid(row=0, column=i, sticky='nsew', padx=(0 if i == 0 else 6, 0 if i == 3 else 6))
            self._label(card, title, 9, COLORS['muted']).pack(anchor='w', padx=14, pady=(8, 0))
            number = self._label(card, '—', 22, color, True)
            number.pack(anchor='w', padx=14)
            self.metric_values.append(number)
            caption_label = self._label(card, caption, 8, COLORS['muted'])
            caption_label.pack(anchor='w', padx=14, pady=(0, 8))
            self.metric_captions.append(caption_label)

        self.notice = self._label(main, 'Pilih folder proyek atau file .py. Kode dianalisis tanpa dijalankan.', 10, COLORS['muted'], anchor='w')
        self.notice.grid(row=3, column=0, sticky='ew', pady=(0, 6))
        self.content = tk.Frame(main, bg=COLORS['bg'])
        self.content.grid(row=4, column=0, sticky='nsew')
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)
        self.views = {}
        self._build_analysis_view()
        self._build_entries_view()
        self._build_notes_view()
        self._build_json_view()
        self._show_view('analysis')
        footer = tk.Frame(main, bg=COLORS['bg'])
        footer.grid(row=5, column=0, sticky='ew', pady=(10, 0))
        self.status_label = self._label(footer, '', 9, COLORS['muted'], anchor='w')
        self.status_label.configure(textvariable=self.status)
        self.status_label.pack(side='left', fill='x', expand=True)
        self._label(footer, 'Ctrl+O  Buka    ·    F5  Analisis', 9, COLORS['muted']).pack(side='right')

    def _build_sidebar(self, sidebar):
        brand = tk.Frame(sidebar, bg=COLORS['sidebar'])
        brand.pack(fill='x', padx=16, pady=(28, 28))
        icon = tk.Canvas(brand, width=35, height=39, bg=COLORS['sidebar'], highlightthickness=0)
        icon.pack(side='left', padx=(0, 8))
        icon.create_polygon(17, 2, 32, 8, 30, 25, 17, 37, 4, 25, 2, 8, fill='#7868F0', outline='')
        icon.create_line(10, 18, 15, 23, 25, 12, fill='white', width=2)
        self._label(brand, 'FlaskGuard', 14, 'white', True).pack(anchor='w')
        self._label(brand, 'CODE SECURITY', 8, '#8797B5', True).pack(anchor='w')
        self._label(sidebar, 'TINJAU KODE', 8, '#7D8CA7', True).pack(anchor='w', padx=23, pady=(0, 10))
        self.nav_buttons = {}
        for key, label in [('analysis', '01   Hasil analisis'), ('entries', '02   Entry point'), ('notes', '03   Catatan analisis'), ('json', '04   Laporan JSON')]:
            btn = tk.Button(sidebar, text=label, anchor='w', command=lambda k=key: self._show_view(k),
                            font=('Segoe UI', 10), bg=COLORS['sidebar'], fg='#A8B5CC', activebackground=COLORS['nav'],
                            activeforeground='white', relief='flat', bd=0, padx=13, pady=13, cursor='hand2')
            btn.pack(fill='x', padx=10, pady=3)
            self.nav_buttons[key] = btn
        bottom = tk.Frame(sidebar, bg=COLORS['sidebar'])
        bottom.pack(side='bottom', fill='x', padx=22, pady=25)
        self._label(bottom, '●  Analisis lokal', 10, '#88D8BC', True).pack(anchor='w')
        self._label(bottom, '6 kategori injeksi\nFile tetap di perangkatmu.', 9, '#91A0BB', justify='left', anchor='w', wraplength=154).pack(anchor='w', pady=(8, 0))

    def _resize_layout(self, event=None):
        if event is not None and event.widget is not self:
            return
        compact = self.winfo_height() < 760
        if compact == self._compact:
            return
        self._compact = compact
        self.main_title.configure(font=('Segoe UI', 18 if compact else 22, 'bold'))
        if compact:
            self.subtitle.pack_forget()
            for caption in self.metric_captions:
                caption.pack_forget()
        else:
            self.subtitle.pack(anchor='w')
            for caption in self.metric_captions:
                caption.pack(anchor='w', padx=14, pady=(0, 8))
        for number in self.metric_values:
            number.configure(font=('Segoe UI', 17 if compact else 22, 'bold'))
        ttk.Style(self).configure('Treeview', rowheight=32 if compact else 42)
        ttk.Style(self).configure('TCombobox', padding=4 if compact else 8)

    def _view(self, key):
        frame = tk.Frame(self.content, bg=COLORS['bg'])
        frame.grid(row=0, column=0, sticky='nsew')
        self.views[key] = frame
        return frame

    def _show_view(self, key):
        if not hasattr(self, 'views') or key not in self.views:
            return
        self._current_view = key
        self.views[key].tkraise()
        for name, btn in self.nav_buttons.items():
            btn.configure(bg=COLORS['nav'] if name == key else COLORS['sidebar'], fg='white' if name == key else '#A8B5CC')

    def _table(self, parent, columns):
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        tree = ttk.Treeview(parent, columns=[c[0] for c in columns], show='headings', selectmode='browse')
        for key, title, width in columns:
            tree.heading(key, text=title)
            tree.column(key, width=max(width, 78), minwidth=78 if key == 'line' else 100, anchor='w')
        tree.grid(row=0, column=0, sticky='nsew')
        vertical = ttk.Scrollbar(parent, orient='vertical', command=tree.yview)
        vertical.grid(row=0, column=1, sticky='ns')
        horizontal = ttk.Scrollbar(parent, orient='horizontal', command=tree.xview)
        horizontal.grid(row=1, column=0, sticky='ew')
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        return tree

    def _build_analysis_view(self):
        view = self._view('analysis')
        panes = tk.PanedWindow(view, orient='horizontal', bg=COLORS['bg'], sashwidth=12, bd=0, sashrelief='flat', opaqueresize=True)
        panes.pack(fill='both', expand=True)
        listing = self._card(panes)
        listing.grid_columnconfigure(0, weight=1)
        listing.grid_rowconfigure(2, weight=1)
        panes.add(listing, minsize=360, stretch='always')
        title = tk.Frame(listing, bg='white')
        title.grid(row=0, column=0, sticky='ew', padx=16, pady=(14, 10))
        self._label(title, 'Daftar alur', 13, bold=True).pack(side='left')
        self.result_count = self._label(title, 'Belum ada analisis', 9, COLORS['muted'])
        self.result_count.pack(side='right')
        filters = tk.Frame(listing, bg='white')
        filters.grid(row=1, column=0, sticky='ew', padx=14, pady=(0, 6))
        filters.grid_columnconfigure(1, weight=1)
        self._label(filters, 'Cari', 9, COLORS['muted']).grid(row=0, column=0, padx=(0, 7))
        self.search_entry = ttk.Entry(filters, textvariable=self.search, width=12)
        self.search_entry.grid(row=0, column=1, sticky='ew', padx=(0, 8))
        ttk.Combobox(filters, textvariable=self.filter, values=list(FILTERS), state='readonly', width=14).grid(row=0, column=2)
        self.file_selector = ttk.Combobox(filters, textvariable=self.file_filter, values=['Semua file'], state='readonly')
        self.file_selector.grid(row=1, column=0, columnspan=3, sticky='ew', pady=(2, 0))
        table_frame = tk.Frame(listing, bg='white')
        table_frame.grid(row=2, column=0, sticky='nsew', padx=1)
        self.findings = self._table(table_frame, [('category', 'KATEGORI', 175), ('status', 'STATUS', 120), ('line', 'BARIS', 65), ('entry', 'FUNGSI', 110), ('file', 'FILE', 240)])
        self.findings.tag_configure('vulnerable', foreground=COLORS['red'])
        self.findings.tag_configure('needs_review', foreground=COLORS['amber'])
        self.findings.tag_configure('sanitized', foreground=COLORS['green'])
        self.findings.bind('<<TreeviewSelect>>', self._select_finding)
        self.empty = tk.Frame(table_frame, bg='white')
        self.empty.place(relx=.5, rely=.52, anchor='center')
        self.empty_title = self._label(self.empty, 'Mulai dari folder proyek.', 16, bold=True)
        self.empty_title.pack()
        self.empty_hint = self._label(self.empty, 'Pilih kode Flask untuk melihat\naliran input dan kandidat injeksi.', 10, COLORS['muted'], justify='center')
        self.empty_hint.pack(pady=(8, 0))

        detail = self._card(panes, width=340)
        panes.add(detail, minsize=280, width=345, stretch='never')
        self._label(detail, 'DETAIL ALUR', 9, COLORS['muted'], True).pack(anchor='w', padx=18, pady=(16, 8))
        self.detail_title = self._label(detail, 'Pilih sebuah alur', 16, bold=True, anchor='w')
        self.detail_title.pack(fill='x', padx=18)
        self.detail_badge = self._label(detail, 'Source  →  Sink', 9, COLORS['accent'], True, anchor='w')
        self.detail_badge.pack(fill='x', padx=18, pady=(6, 12))
        self.detail_text = self._text_panel(detail, wrap='word', font=('Segoe UI', 10))
        self.detail_text.tag_configure('section', font=('Segoe UI', 9, 'bold'), foreground=COLORS['muted'], spacing1=18, spacing3=6)
        self.detail_text.tag_configure('step', font=('Segoe UI', 9, 'bold'), foreground=COLORS['accent'], spacing1=12, spacing3=4)
        self.detail_text.tag_configure('code', font=('Consolas', 10), foreground='#35435C', background='#F3F5FA', spacing1=4, spacing3=4)
        self.detail_text.tag_configure('muted', foreground=COLORS['muted'])
        self._reset_detail()

    def _text_panel(self, parent, wrap='word', font=('Consolas', 10)):
        frame = tk.Frame(parent, bg='white')
        frame.pack(fill='both', expand=True, padx=14, pady=(0, 14))
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        text = tk.Text(frame, wrap=wrap, font=font, bg='white', fg=COLORS['ink'], relief='flat', bd=0,
                       padx=4, pady=8, spacing1=3, spacing3=3, highlightthickness=0, state='disabled', width=20, height=6)
        text.grid(row=0, column=0, sticky='nsew')
        scrollbar = ttk.Scrollbar(frame, orient='vertical', command=text.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        text.configure(yscrollcommand=scrollbar.set)
        if wrap == 'none':
            horizontal = ttk.Scrollbar(frame, orient='horizontal', command=text.xview)
            horizontal.grid(row=1, column=0, sticky='ew')
            text.configure(xscrollcommand=horizontal.set)
        return text

    def _build_entries_view(self):
        view = self._view('entries')
        card = self._card(view)
        card.pack(fill='both', expand=True)
        self._label(card, 'Entry point Flask', 16, bold=True).pack(anchor='w', padx=20, pady=(18, 6))
        self._label(card, 'Fungsi yang dikenali sebagai titik masuk analisis.', 10, COLORS['muted']).pack(anchor='w', padx=20, pady=(0, 15))
        container = tk.Frame(card, bg='white')
        container.pack(fill='both', expand=True, padx=1, pady=(0, 1))
        self.entries = self._table(container, [('name', 'FUNGSI / CLASS', 230), ('kind', 'TIPE', 150), ('line', 'BARIS', 70), ('decorators', 'DECORATOR', 340), ('file', 'FILE', 240)])

    def _build_notes_view(self):
        view = self._view('notes')
        card = self._card(view)
        card.pack(fill='both', expand=True)
        self._label(card, 'Cakupan & catatan analisis', 16, bold=True).pack(anchor='w', padx=20, pady=(18, 6))
        self._label(card, 'Gunakan catatan ini untuk memahami bagian kode yang masih memerlukan pemeriksaan.', 10, COLORS['muted']).pack(anchor='w', padx=20, pady=(0, 14))
        self.notes_output = self._text_panel(card, font=('Segoe UI', 11))
        self._set_text(self.notes_output, 'Catatan akan muncul setelah file dianalisis.')

    def _build_json_view(self):
        view = self._view('json')
        card = self._card(view)
        card.pack(fill='both', expand=True)
        toolbar = tk.Frame(card, bg='white')
        toolbar.pack(fill='x', padx=20, pady=(12, 8))
        self._label(toolbar, 'Laporan terstruktur', 16, bold=True).pack(side='left')
        self.copy_button = self._button(toolbar, 'Salin JSON', self._copy_json)
        self.copy_button.pack(side='right')
        self.copy_button.configure(state='disabled')
        self.json_output = self._text_panel(card, wrap='none')
        self._set_text(self.json_output, 'Belum ada laporan. Jalankan analisis untuk melihat hasil JSON.')

    @staticmethod
    def _set_text(widget, text):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.configure(state='disabled')

    def _reset_detail(self):
        self.detail_title.configure(text='Pilih sebuah alur')
        self.detail_badge.configure(text='Source  →  Sink', fg=COLORS['accent'])
        self._set_text(self.detail_text, 'Klik baris pada daftar untuk melihat alasan pelaporan, jejak input, dan potongan kode.\n\nKandidat perlu ditinjau sebelum disimpulkan sebagai kerentanan yang dapat dieksploitasi.')

    def _choose_folder(self):
        if self._busy:
            return
        selected = filedialog.askdirectory(parent=self, title='Pilih folder utama proyek Flask')
        if selected:
            self.path.set(selected)
            self.status.set('Folder dipilih. Semua file .py di dalam subfolder akan dipindai.')

    def _choose_file(self):
        if self._busy:
            return
        selected = filedialog.askopenfilename(parent=self, title='Pilih kode sumber Flask', filetypes=[('Python', '*.py')])
        if selected:
            self.path.set(selected)
            self.status.set('File dipilih. Klik Mulai analisis untuk memindai.')
            self.path_entry.focus_set()

    def _clear_results(self):
        self.result = None
        self.file_filter.set('Semua file')
        self.file_selector.configure(values=['Semua file'])
        self._rows.clear()
        for tree in (self.findings, self.entries):
            tree.delete(*tree.get_children())
        for number in self.metric_values:
            number.configure(text='—')
        self.export_button.configure(state='disabled')
        self.copy_button.configure(state='disabled')
        self.result_count.configure(text='Belum ada hasil')
        self._reset_detail()
        self._set_text(self.json_output, 'Belum ada laporan untuk analisis ini.')
        self._set_text(self.notes_output, 'Belum ada catatan untuk analisis ini.')

    def _scan(self):
        if self._busy:
            return
        target = self.path.get().strip().strip('"')
        if not target:
            self.status.set('Pilih folder proyek atau file .py terlebih dahulu.')
            self.path_entry.focus_set()
            return
        self._clear_results()
        self._busy = True
        self.scan_button.configure(state='disabled', text='Menganalisis…')
        self.choose_button.configure(state='disabled')
        self.folder_button.configure(state='disabled')
        self.path_entry.configure(state='disabled')
        self.progress.start(12)
        self.notice.configure(text='Menganalisis ' + Path(target).name + ' …', fg=COLORS['accent'])
        self.status.set('Analisis sedang berjalan. File target tidak dieksekusi.')
        self.empty_title.configure(text='Menelusuri aliran input…')
        self.empty_hint.configure(text='Hasil akan ditampilkan setelah analisis selesai.')
        self.empty.place(relx=.5, rely=.52, anchor='center')
        self._show_view('analysis')
        # The worker never touches Tk. Results are consumed on the UI thread.
        def work():
            try:
                if Path(target).is_dir():
                    result = scan_project(Path(target), lambda i, total, name: self._messages.put(('progress', f'{i}/{total} file: {name}')))
                else:
                    result = analyze_taint_file(Path(target))
                self._messages.put((result, None))
            except Exception as error:
                self._messages.put((None, str(error) or type(error).__name__))
        threading.Thread(target=work, daemon=True).start()

    def _poll_scan(self):
        try:
            result, error = self._messages.get_nowait()
        except queue.Empty:
            pass
        else:
            if result == 'progress':
                self.status.set(error)
                self.after(20, self._poll_scan)
                return
            self._busy = False
            self.progress.stop()
            self.progress.configure(value=0)
            self.scan_button.configure(state='normal', text='Mulai analisis  →')
            self.choose_button.configure(state='normal')
            self.folder_button.configure(state='normal')
            self.path_entry.configure(state='normal')
            if error is not None:
                self.notice.configure(text='Analisis gagal. Periksa file yang dipilih.', fg=COLORS['red'])
                self.status.set('Gagal menganalisis file; tidak ada laporan yang disimpan.')
                self.empty_title.configure(text='File belum bisa dianalisis')
                self.empty_hint.configure(text='Periksa sintaks dan akses file, lalu coba lagi.')
                self._set_text(self.notes_output, error)
                messagebox.showerror('Analisis gagal', error, parent=self)
            else:
                self._render_result(result)
        self.after(80, self._poll_scan)

    def _render_result(self, result):
        self.result = result
        counts = (result.vulnerable_count, result.review_count, result.sanitized_count, len(result.parser_result.entry_points))
        for widget, count in zip(self.metric_values, counts):
            widget.configure(text=f'{count:02d}')
        self.entries.delete(*self.entries.get_children())
        file_results = result.results if isinstance(result, ProjectResult) else [result]
        self.file_selector.configure(values=['Semua file'] + [r.parser_result.filename for r in file_results])
        for file_result in file_results:
            for entry in file_result.parser_result.entry_points:
                self.entries.insert('', 'end', values=(entry.name, entry.kind, entry.location.line, ', '.join(entry.decorators) or '—', file_result.parser_result.filename))
        self._set_text(self.json_output, json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        notes = ['STATUS CAKUPAN', 'Analisis parsial. Sebagian konstruksi belum dapat dianalisis.' if result.coverage_issues else 'Analisis selesai dalam cakupan model yang didukung.', '', 'CATATAN']
        notes.extend(f'{i+1}. {text}' for i, text in enumerate(result.diagnostics))
        if not result.diagnostics:
            notes.append('Tidak ada catatan tambahan dari engine.')
        if result.coverage_issues:
            notes.extend(['', 'BAGIAN YANG PERLU DITINJAU'])
            notes.extend(f"• Baris {item['line']} · {item['entry_point']}\n  {item['reason']}" for item in result.coverage_issues)
        notes.extend(['', 'Hasil tanpa kandidat bukan jaminan bahwa aplikasi bebas kerentanan.'])
        self._set_text(self.notes_output, '\n'.join(notes))
        if result.coverage_issues:
            message = '●  Tidak ada kandidat pada bagian yang teranalisis; cakupan masih parsial.' if not (result.vulnerable_count + result.review_count) else '●  Analisis parsial. Buka Catatan analisis untuk melihat batas cakupan.'
            self.notice.configure(text=message, fg=COLORS['amber'])
        else:
            message = '●  Tidak ada kandidat dalam cakupan model; bukan jaminan aman.' if not (result.vulnerable_count + result.review_count) else '●  Analisis selesai. Temuan adalah kandidat untuk pemeriksaan lebih lanjut.'
            self.notice.configure(text=message, fg=COLORS['green'])
        self.status.set('Hasil: ' + Path(result.parser_result.filename).name)
        if isinstance(result, ProjectResult):
            self.status.set(f'{len(result.results)} file dianalisis | {len(result.errors)} error | {len(result.skipped)} dilewati | pilih file pada filter untuk meninjau')
        self.export_button.configure(state='normal')
        self.copy_button.configure(state='normal')
        self._filter_findings()

    def _filter_findings(self):
        if not hasattr(self, 'findings') or self.result is None:
            return
        self.findings.delete(*self.findings.get_children())
        self._rows.clear()
        term = self.search.get().casefold().strip()
        wanted = FILTERS.get(self.filter.get())
        for index, flow in enumerate(self.result.vulnerabilities):
            owner = self.result.owner(flow) if isinstance(self.result, ProjectResult) else self.result
            filename = owner.parser_result.filename
            if self.file_filter.get() not in ('Semua file', filename):
                continue
            searchable = ' '.join((filename, flow.vulnerability_type, flow.entry_point, flow.source, flow.sink, flow.cwe, flow.rule_id)).casefold()
            if (wanted and flow.status != wanted) or (term and term not in searchable):
                continue
            key = str(index)
            self._rows[key] = flow
            self.findings.insert('', 'end', iid=key, values=(flow.vulnerability_type, STATUS_LABELS.get(flow.status, flow.status), flow.path[-1].line, flow.entry_point, filename), tags=(flow.status,))
        count = len(self._rows)
        self.result_count.configure(text=f'{count} / {len(self.result.vulnerabilities)} alur')
        if count:
            self.empty.place_forget()
            key = next(iter(self._rows))
            self.findings.selection_set(key)
            self.findings.focus(key)
            self._select_finding()
        else:
            self._reset_detail()
            self.empty_title.configure(text='Tidak ada alur yang cocok' if self.result.vulnerabilities else ('Belum ada kandidat; parsial' if self.result.coverage_issues else 'Tidak ada kandidat'))
            self.empty_hint.configure(text='Ubah kata pencarian atau filter status.' if self.result.vulnerabilities else 'Lihat Catatan analisis untuk memahami\ncakupan pemeriksaan file ini.')
            self.empty.place(relx=.5, rely=.52, anchor='center')

    def _select_finding(self, _event=None):
        selected = self.findings.selection()
        if not selected or selected[0] not in self._rows:
            return
        flow = self._rows[selected[0]]
        color = {'vulnerable': COLORS['red'], 'needs_review': COLORS['amber'], 'sanitized': COLORS['green']}.get(flow.status, COLORS['ink'])
        self.detail_title.configure(text=flow.vulnerability_type)
        self.detail_badge.configure(text=f'{STATUS_LABELS.get(flow.status, flow.status)}   ·   {flow.cwe}   ·   Baris {flow.path[-1].line}', fg=color)
        text = self.detail_text
        text.configure(state='normal')
        text.delete('1.0', 'end')
        text.insert('end', 'ALASAN PELAPORAN\n', 'section')
        text.insert('end', flow.explanation + '\n')
        text.insert('end', 'JEJAK ALIRAN DATA\n', 'section')
        for index, step in enumerate(flow.path, 1):
            text.insert('end', f'{index:02d}  {STEP_LABELS.get(step.kind, step.kind)}  ·  L{step.line}\n', 'step')
            text.insert('end', step.label + '\n', 'code')
        text.insert('end', 'KODE DI SEKITAR SINK\n', 'section')
        owner = self.result.owner(flow) if isinstance(self.result, ProjectResult) else self.result
        text.insert('end', owner.parser_result.filename + '\n', 'muted')
        lines = (owner.parser_result.source_code or '').splitlines()
        line = flow.path[-1].line
        for number in range(max(1, line-2), min(len(lines), line+2)+1):
            text.insert('end', f'{"›" if number == line else " "} {number:>3}  {lines[number-1]}\n', 'code')
        text.insert('end', 'IDENTITAS ATURAN\n', 'section')
        text.insert('end', flow.rule_id + '\n', 'code')
        text.insert('end', 'KONTEKS & BATASAN\n', 'section')
        text.insert('end', 'Argumen: ' + ', '.join(flow.sensitive_arguments) + '\n')
        text.insert('end', 'Jenis risiko: ' + flow.risk_kind + '\n')
        text.insert('end', '\n'.join(flow.call_conditions) + '\n')
        if flow.limitations:
            text.insert('end', '\n'.join(flow.limitations) + '\n', 'muted')
        text.insert('end', f'\nFungsi: {flow.entry_point}\nSumber: {flow.source}\nSink: {flow.sink}', 'muted')
        text.configure(state='disabled')
        text.yview_moveto(0)

    def _copy_json(self):
        if self.result is None:
            return
        self.clipboard_clear()
        self.clipboard_append(json.dumps(self.result.to_dict(), indent=2, ensure_ascii=False))
        self.status.set('Laporan JSON disalin ke clipboard.')

    def _save_report(self):
        if self.result is None or self._busy:
            return
        filename = Path(self.result.parser_result.filename).stem + '-report.json'
        selected = filedialog.asksaveasfilename(parent=self, title='Ekspor laporan analisis', initialfile=filename, defaultextension='.json', filetypes=[('JSON', '*.json')])
        if selected:
            try:
                Path(selected).write_text(json.dumps(self.result.to_dict(), indent=2, ensure_ascii=False), encoding='utf-8')
            except OSError as error:
                messagebox.showerror('Ekspor gagal', str(error), parent=self)
            else:
                self.status.set('Laporan disimpan: ' + Path(selected).name)


def main():
    ScannerApp().mainloop()


if __name__ == '__main__':
    main()
