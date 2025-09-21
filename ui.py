"""
Pure Tkinter GUI — no packet logic.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from matplotlib.animation import FuncAnimation
import threading
import time

class ModernPacketSnifferUI:
    def __init__(self,
                 start_capture_callback,
                 stop_capture_callback,
                 pause_resume_callback,
                 restart_callback,
                 export_pcap_callback,
                 import_pcap_callback,
                 export_log_callback,
                 export_suspicious_callback,
                 clear_suspicious_callback,
                 toggle_theme_callback,
                 replay_packet_callback,
                 on_filter_change_callback,
                 on_ip_filter_change_callback,
                 get_packet_handler_data_callback):
        """
        Initialize UI with callbacks to App/Controller.
        """
        self.root = tk.Tk()
        self.root.title("🌐 NETWORK MONITORING DASHBOARD")
        self.root.geometry("1600x900")
        self.root.minsize(1300, 850)

        # Callbacks
        self.start_capture_callback = start_capture_callback
        self.stop_capture_callback = stop_capture_callback
        self.pause_resume_callback = pause_resume_callback
        self.restart_callback = restart_callback
        self.export_pcap_callback = export_pcap_callback
        self.import_pcap_callback = import_pcap_callback
        self.export_log_callback = export_log_callback
        self.export_suspicious_callback = export_suspicious_callback
        self.clear_suspicious_callback = clear_suspicious_callback
        self.toggle_theme_callback = toggle_theme_callback
        self.replay_packet_callback = replay_packet_callback
        self.on_filter_change_callback = on_filter_change_callback
        self.on_ip_filter_change_callback = on_ip_filter_change_callback
        self.get_packet_handler_data_callback = get_packet_handler_data_callback

        # Theme
        self.dark_mode = False
        self.COLORS = {
            "primary": "#28a745",  # Green
            "secondary": "#ffc107",  # Yellow
            "hover": "#F58321",  # Orange
            "danger": "#dc3545",  # Red
            "success": "#28a745",  # Green
            "info": "#17a2b8",  # Teal
            "bg_light": "#f8f9fa",  # Light background
            "text_main": "#212529",  # Dark text
            "text_muted": "#6c757d"  # Muted text
        }

        # Bandwidth animation
        self.bandwidth_animation = None

        # Build UI
        self.setup_menu()
        self.setup_status_bar()
        self.setup_main_frame()
        self.setup_control_panel()
        self.setup_tabs()
        self.apply_theme()
        self.animate_status()

    def setup_menu(self):
        menubar = Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export PCAP", command=self.export_pcap_callback)
        file_menu.add_command(label="Import PCAP", command=self.import_pcap_callback)
        file_menu.add_separator()
        file_menu.add_command(label="Export Log", command=self.export_log_callback)
        menubar.add_cascade(label="File", menu=file_menu)

        view_menu = Menu(menubar, tearoff=0)
        view_menu.add_command(label="Toggle Theme", command=self.toggle_theme_callback)
        menubar.add_cascade(label="View", menu=view_menu)

    def setup_status_bar(self):
        self.status_var = tk.StringVar()
        self.status_var.set("🚀 SYSTEM READY | No packets captured yet")
        self.status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            anchor=tk.W,
            background=self.COLORS["bg_light"],
            foreground=self.COLORS["text_main"],
            font=("Segoe UI", 10, "bold")
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, ipady=8)

    def setup_main_frame(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill='both', expand=True, padx=15, pady=15)

    def setup_control_panel(self):
        """Enhanced control panel with better button styling, spacing, and Exit button."""
        control_frame = ttk.Frame(self.main_frame)
        control_frame.pack(fill='x', pady=(0, 20))  # More bottom padding

        # Configure grid for responsiveness
        for i in range(12):  # 12 columns for flexible layout
            control_frame.grid_columnconfigure(i, weight=1)

        # Button style config — more padding, consistent width
        button_config = {
            'font': ("Segoe UI", 10, "bold"),
            'padding': (10, 6),  # Increased padding
        }

        # Start Button
        self.btn_start = ttk.Button(control_frame, text="▶ Start Capture", command=self.start_capture_callback,
                                    style='TButton')
        self.btn_start.configure(width=15)  # Wider for text
        self.btn_start.grid(row=0, column=0, padx=4, pady=5, sticky='ew')

        # Pause Button
        self.btn_pause = ttk.Button(control_frame, text="⏸ Pause", command=self.pause_resume_callback, state='disabled',
                                    style='TButton')
        self.btn_pause.configure(width=12)
        self.btn_pause.grid(row=0, column=1, padx=4, pady=5, sticky='ew')

        # Stop Button
        self.btn_stop = ttk.Button(control_frame, text="⏹ Stop Capture", command=self.stop_capture_callback,
                                   state='disabled', style='Stop.TButton')
        self.btn_stop.configure(width=15)
        self.btn_stop.grid(row=0, column=2, padx=4, pady=5, sticky='ew')

        # Restart Button
        self.btn_restart = ttk.Button(control_frame, text="🔄 Restart", command=self.restart_callback, style='TButton')
        self.btn_restart.configure(width=12)
        self.btn_restart.grid(row=0, column=3, padx=4, pady=5, sticky='ew')

        # Export PCAP
        self.btn_export_pcap = ttk.Button(control_frame, text="💾 Export PCAP", command=self.export_pcap_callback,
                                          style='TButton')
        self.btn_export_pcap.configure(width=14)
        self.btn_export_pcap.grid(row=0, column=4, padx=4, pady=5, sticky='ew')

        # Import PCAP
        self.btn_import_pcap = ttk.Button(control_frame, text="📂 Import PCAP", command=self.import_pcap_callback,
                                          style='TButton')
        self.btn_import_pcap.configure(width=14)
        self.btn_import_pcap.grid(row=0, column=5, padx=4, pady=5, sticky='ew')

        # Export Log
        self.btn_export_log = ttk.Button(control_frame, text="📤 Export Log", command=self.export_log_callback,
                                         style='TButton')
        self.btn_export_log.configure(width=13)
        self.btn_export_log.grid(row=0, column=6, padx=4, pady=5, sticky='ew')

        # ✅ EXIT BUTTON — New!
        self.btn_exit = ttk.Button(control_frame, text="🚪 Exit", command=self.exit_app, style='Stop.TButton')
        self.btn_exit.configure(width=10)
        self.btn_exit.grid(row=0, column=7, padx=4, pady=5, sticky='ew')

        # Filters — moved to next row for breathing room
        filter_frame = ttk.Frame(control_frame)
        filter_frame.grid(row=1, column=0, columnspan=8, sticky='ew', pady=(10, 0))

        ttk.Label(filter_frame, text="🔍 Filter:", font=("Segoe UI", 9, "bold")).pack(side='left', padx=(0, 8))
        self.filter_var = tk.StringVar()
        self.filter_var.trace('w', lambda *args: self.on_filter_change_callback(self.filter_var.get()))
        self.filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=30, font=("Segoe UI", 9))
        self.filter_entry.pack(side='left', padx=5, ipady=3)

        ttk.Label(filter_frame, text=" 🎯 IP:", font=("Segoe UI", 9, "bold")).pack(side='left', padx=(15, 8))
        self.ip_filter_var = tk.StringVar()
        self.ip_filter_var.trace('w', lambda *args: self.on_ip_filter_change_callback(self.ip_filter_var.get()))
        self.ip_filter_entry = ttk.Entry(filter_frame, textvariable=self.ip_filter_var, width=18, font=("Segoe UI", 9))
        self.ip_filter_entry.pack(side='left', padx=5, ipady=3)

        # Apply button styles
        style = ttk.Style()
        style.configure('TButton', **button_config)
        style.configure('Stop.TButton', **button_config)
    def exit_app(self):
        """Exit application with confirmation dialog."""
        ph_data = self.get_packet_handler_data_callback()
        if ph_data.get('is_capturing', False):
            confirm = messagebox.askyesno(
                "⚠️ Confirm Exit",
                "Packet capture is still running.\nDo you want to stop and exit?",
                icon='warning'
            )
            if confirm:
                self.stop_capture_callback()  # Gracefully stop capture
                self.root.after(500, self.root.destroy)  # Small delay for cleanup
        else:
            confirm = messagebox.askyesno(
                "🚪 Confirm Exit",
                "Are you sure you want to exit the Network Monitor?",
                icon='question'
            )
            if confirm:
                self.root.destroy()
    def setup_tabs(self):
        self.notebook = ttk.Notebook(self.main_frame)
        style = ttk.Style()
        style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[12, 6])
        self.notebook.pack(fill='both', expand=True)

        self.setup_live_tab()
        self.setup_summary_tab()
        self.setup_geo_tab()
        self.setup_suspicious_tab()

    def setup_live_tab(self):
        self.tab_live = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_live, text="📡 Live Feed")

        tree_frame = ttk.Frame(self.tab_live)
        tree_frame.pack(fill='both', expand=True)

        columns = ("ID", "Time", "Src", "SrcPort", "Dst", "DstPort", "Proto", "Type", "Size", "Payload", "HTTP/DNS", "Anomaly")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', selectmode="extended")

        col_widths = {
            "ID": 40, "Time": 70, "Src": 110, "SrcPort": 60, "Dst": 110, "DstPort": 60,
            "Proto": 60, "Type": 60, "Size": 60, "Payload": 110, "HTTP/DNS": 180, "Anomaly": 60
        }
        for col in columns:
            self.tree.heading(col, text=col, command=lambda _col=col: self.sort_column(_col, False))
            anchor = 'center' if col in ["ID", "Time", "SrcPort", "DstPort", "Proto", "Type", "Size", "Anomaly"] else 'w'
            self.tree.column(col, width=col_widths[col], anchor=anchor)

        style = ttk.Style()
        style.configure("Treeview.Heading",
                        background=self.COLORS["primary"],
                        foreground="white",
                        font=('Segoe UI', 9, 'bold'),
                        padding=4,
                        relief="flat"
                        )
        try:
            style.map("Treeview.Heading",
                      background=[('active', self.COLORS["hover"])],
                      foreground=[('active', 'white')]
                      )
        except:
            pass

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Right-click menu
        self.tree_menu = Menu(self.root, tearoff=0)
        self.tree_menu.add_command(label="🔁 Replay", command=self.replay_selected)
        self.tree.bind("<Button-3>", self.show_tree_menu)
        self.tree.bind("<<TreeviewSelect>>", self.show_packet_details)

        # Details Panel
        self.details_text = scrolledtext.ScrolledText(
            self.tab_live, height=8, wrap=tk.WORD, font=("Consolas", 9, "bold"),
            bg=self.COLORS["bg_light"], fg=self.COLORS["text_main"]
        )
        self.details_text.pack(fill='x', pady=(10, 0))
        self.details_text.config(state='disabled')

    def setup_summary_tab(self):
        self.tab_summary = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_summary, text="📊 Summary")

        # Create figure with 2x3 subplots
        self.fig = Figure(figsize=(14, 9), dpi=100)
        self.fig.patch.set_facecolor(self.COLORS["bg_light"])
        self.ax1 = self.fig.add_subplot(2, 3, 1)  # Protocol Distribution
        self.ax2 = self.fig.add_subplot(2, 3, 2)  # Traffic Safety
        self.ax3 = self.fig.add_subplot(2, 3, 3)  # Top Countries
        self.ax4 = self.fig.add_subplot(2, 3, 4)  # Protocol Trends
        self.ax5 = self.fig.add_subplot(2, 3, 5)  # Packets per Second
        self.ax6 = self.fig.add_subplot(2, 3, 6)  # Bytes per Second

        self.canvas = FigureCanvasTkAgg(self.fig, self.tab_summary)
        self.canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

        # ✅ BANDWIDTH GRAPHS INIT
        self.ax5.set_title('Packets per Second', color=self.COLORS["text_main"], fontweight='bold', fontsize=11)
        self.ax5.set_xlabel('Time (s)', fontweight='bold', fontsize=10)
        self.ax5.set_ylabel('Packets', fontweight='bold', fontsize=10)
        self.ax5.grid(alpha=0.3)
        self.ax5_line, = self.ax5.plot([], [], color=self.COLORS["primary"], linewidth=2)

        self.ax6.set_title('Bytes per Second', color=self.COLORS["text_main"], fontweight='bold', fontsize=11)
        self.ax6.set_xlabel('Time (s)', fontweight='bold', fontsize=10)
        self.ax6.set_ylabel('Bytes', fontweight='bold', fontsize=10)
        self.ax6.grid(alpha=0.3)
        self.ax6_line, = self.ax6.plot([], [], color=self.COLORS["info"], linewidth=2)

        # Enhanced Geo Summary Panel
        geo_summary_frame = ttk.LabelFrame(self.tab_summary, text="🌍 GeoIP Summary", padding=8)
        geo_summary_frame.pack(fill='x', padx=10, pady=10)
        self.geo_summary_text = scrolledtext.ScrolledText(
            geo_summary_frame, height=6, wrap=tk.WORD, font=("Consolas", 9, "bold"),
            bg=self.COLORS["bg_light"], fg=self.COLORS["text_main"]
        )
        self.geo_summary_text.pack(fill='both', expand=True)
        self.geo_summary_text.insert(tk.END, "Start capture to see GeoIP summary...")
        self.geo_summary_text.config(state='disabled')

        # Start bandwidth animation
        self.start_bandwidth_animation()

    def setup_geo_tab(self):
        self.tab_geo = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_geo, text="🗺️ Geo Locations")

        header_frame = ttk.Frame(self.tab_geo)
        header_frame.pack(fill='x', padx=10, pady=(10, 5))
        ttk.Label(header_frame, text="📍 IP Location Details", font=("Segoe UI", 11, "bold")).pack(side='left')
        self.btn_refresh_geo = ttk.Button(header_frame, text="🔄 Refresh", command=self.update_geo_tab, style='TButton')
        self.btn_refresh_geo.pack(side='right', padx=10)

        geo_columns = ("ID", "IP", "Country", "City", "Region", "Latitude", "Longitude")
        self.geo_tree = ttk.Treeview(self.tab_geo, columns=geo_columns, show='headings', selectmode="browse")
        geo_col_widths = {
            "ID": 40, "IP": 130, "Country": 110, "City": 110, "Region": 110, "Latitude": 90, "Longitude": 90
        }
        for col in geo_columns:
            self.geo_tree.heading(col, text=col, command=lambda _col=col: self.sort_geo_column(_col, False))
            anchor = 'center' if col == "ID" else 'w'
            self.geo_tree.column(col, width=geo_col_widths[col], anchor=anchor)

        vsb_geo = ttk.Scrollbar(self.tab_geo, orient="vertical", command=self.geo_tree.yview)
        hsb_geo = ttk.Scrollbar(self.tab_geo, orient="horizontal", command=self.geo_tree.xview)
        self.geo_tree.configure(yscrollcommand=vsb_geo.set, xscrollcommand=hsb_geo.set)
        self.geo_tree.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        vsb_geo.pack(side='right', fill='y')
        hsb_geo.pack(side='bottom', fill='x')

    def setup_suspicious_tab(self):
        self.tab_suspicious = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_suspicious, text="⚠️ Suspicious")

        susp_tree_frame = ttk.Frame(self.tab_suspicious)
        susp_tree_frame.pack(fill='both', expand=True)

        susp_columns = ("ID", "Time", "Src", "Dst", "Reason")
        self.suspicious_tree = ttk.Treeview(susp_tree_frame, columns=susp_columns, show='headings')
        for col in susp_columns:
            self.suspicious_tree.heading(col, text=col)
            self.suspicious_tree.column(col, width=100 if col == "Reason" else 70,
                                        anchor='center' if col != "Reason" else 'w')

        vsb2 = ttk.Scrollbar(susp_tree_frame, orient="vertical", command=self.suspicious_tree.yview)
        self.suspicious_tree.configure(yscrollcommand=vsb2.set)
        self.suspicious_tree.pack(side='left', fill='both', expand=True)
        vsb2.pack(side='right', fill='y')
        self.suspicious_tree.bind("<<TreeviewSelect>>", self.show_suspicious_details)

        self.suspicious_details = scrolledtext.ScrolledText(
            self.tab_suspicious, height=6, font=("Consolas", 9, "bold"),
            bg=self.COLORS["bg_light"], fg=self.COLORS["text_main"]
        )
        self.suspicious_details.pack(fill='x', pady=(10, 0))
        self.suspicious_details.config(state='disabled')

        # Buttons
        btn_frame = ttk.Frame(self.tab_suspicious)
        btn_frame.pack(fill='x', pady=10)
        self.btn_export_suspicious = ttk.Button(btn_frame, text="📤 Export", command=self.export_suspicious_callback, style='TButton')
        self.btn_export_suspicious.pack(side='left', padx=5, ipady=3)
        self.btn_clear_suspicious = ttk.Button(btn_frame, text="🗑️ Clear", command=self.clear_suspicious_callback, style='Stop.TButton')
        self.btn_clear_suspicious.pack(side='left', padx=5, ipady=3)

    def apply_theme(self):
        style = ttk.Style()
        style.theme_use('default')
        bg = self.COLORS["bg_light"]
        fg = self.COLORS["text_main"]
        primary = self.COLORS["primary"]
        secondary = self.COLORS["secondary"]
        hover = self.COLORS["hover"]
        danger = self.COLORS["danger"]

        self.root.configure(bg=bg)

        style.configure('TButton',
                        font=('Segoe UI', 10, 'bold'),
                        padding=6,
                        background=primary,
                        foreground='white',
                        borderwidth=0,
                        relief='flat'
                        )
        style.map('TButton',
                  background=[('active', hover)],
                  foreground=[('active', 'white')]
                  )
        style.configure('Stop.TButton',
                        font=('Segoe UI', 10, 'bold'),
                        padding=6,
                        background=danger,
                        foreground='white',
                        borderwidth=0,
                        relief='flat'
                        )
        style.map('Stop.TButton',
                  background=[('active', '#c82333')],
                  foreground=[('active', 'white')]
                  )
        style.configure('Treeview',
                        background=bg,
                        foreground=fg,
                        fieldbackground=bg,
                        font=('Segoe UI', 9, 'bold'),
                        rowheight=25
                        )
        style.configure('Treeview.Heading',
                        background=primary,
                        foreground='white',
                        font=('Segoe UI', 9, 'bold'),
                        padding=4,
                        relief="flat"
                        )
        try:
            style.map('Treeview.Heading',
                      background=[('active', hover)],
                      foreground=[('active', 'white')]
                      )
        except:
            pass
        style.configure('TLabel', background=bg, foreground=fg, font=('Segoe UI', 9, 'bold'))
        style.configure('TEntry', fieldbackground='white', font=('Segoe UI', 9, 'bold'), padding=4)
        style.configure('TFrame', background=bg)
        style.configure('TLabelframe', background=bg, font=('Segoe UI', 9, 'bold'))
        style.configure('TLabelframe.Label', background=bg, foreground=fg, font=('Segoe UI', 9, 'bold'))

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.COLORS["bg_light"] = "#1e1e1e"
            self.COLORS["text_main"] = "#ffffff"
        else:
            self.COLORS["bg_light"] = "#f8f9fa"
            self.COLORS["text_main"] = "#212529"
        self.apply_theme()
        self.update_all_tabs()

    def animate_status(self):
        ph_data = self.get_packet_handler_data_callback()
        if ph_data.get('is_capturing', False) and not ph_data.get('is_paused', False):
            dots = "." * int((time.time() % 3) + 1)
            self.status_var.set(f"▶ CAPTURING{dots} | Packets: {ph_data.get('total_packets', 0)} | Suspicious: {ph_data.get('suspicious_count', 0)}  | Developed by  Haile T.")
        elif ph_data.get('is_paused', False):
            self.status_var.set("⏸ PAUSED | Click Resume to continue | Developed by Haile T.")
        else:
            self.status_var.set("🚀 SYSTEM READY | Click Start to begin capture | Developed by Haile T.")
        self.root.after(500, self.animate_status)

    def start_bandwidth_animation(self):
        def animate(i):
            ph_data = self.get_packet_handler_data_callback()
            bw_queue = ph_data.get('bandwidth_queue')
            if not bw_queue:
                return self.ax5_line, self.ax6_line
            try:
                while not bw_queue.empty():
                    data = bw_queue.get_nowait()
                    if len(data['times']) > 0:
                        start_time = data['times'][0] if data['times'] else time.time()
                        relative_times = [t - start_time for t in data['times']]
                        self.ax5_line.set_data(relative_times, data['packets_per_sec'])
                        self.ax6_line.set_data(relative_times, data['bytes_per_sec'])
                        if len(relative_times) > 0:
                            self.ax5.set_xlim(0, max(60, relative_times[-1]))
                            self.ax5.set_ylim(0, max(10, max(data['packets_per_sec']) * 1.1) if data['packets_per_sec'] else 10)
                            self.ax6.set_xlim(0, max(60, relative_times[-1]))
                            self.ax6.set_ylim(0, max(1000, max(data['bytes_per_sec']) * 1.1) if data['bytes_per_sec'] else 1000)
                self.fig.canvas.draw()
            except Exception as e:
                print(f"Bandwidth animation error: {e}")
            return self.ax5_line, self.ax6_line

        self.bandwidth_animation = FuncAnimation(self.fig, animate, interval=1000, blit=False, cache_frame_data=False)

    # --- UI Update Methods ---
    def update_all_tabs(self):
        self.update_live_tab()
        self.update_summary_tab()
        self.update_suspicious_tab()
        self.update_geo_tab()

    def update_live_tab_realtime(self):
        if not hasattr(self, 'tree') or not self.tree:
            return
        current_selection = self.tree.selection()
        current_view = self.tree.yview()
        self.update_live_tab()
        if current_selection:
            self.tree.selection_set(current_selection)
        if current_view[1] >= 0.95:
            self.tree.yview_moveto(1.0)

    def update_live_tab(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        ph_data = self.get_packet_handler_data_callback()
        display_packets = ph_data.get('filtered_packets', [])

        for pkt in display_packets[-1000:]:
            values = (
                pkt['id'], pkt['time'], pkt['src'], pkt['src_port'], pkt['dst'], pkt['dst_port'],
                pkt['proto'], pkt['payload_type'], pkt['payload_size'],
                pkt['payload_preview'], pkt['http_dns_info'], pkt['anomaly']
            )
            tags = ()
            if pkt['suspicious']:
                tags = ("suspicious",)
            elif pkt['anomaly']:
                tags = ("anomaly",)
            elif pkt['payload_type'] == "Binary":
                tags = ("binary",)
            elif pkt['payload_size'] > 500:
                tags = ("large",)
            self.tree.insert("", "end", values=values, tags=tags)

        self.tree.tag_configure("suspicious", background=self.COLORS["danger"], foreground="white")
        self.tree.tag_configure("anomaly", background=self.COLORS["secondary"], foreground="black")
        self.tree.tag_configure("binary", background="#e9ecef", foreground=self.COLORS["text_main"])
        self.tree.tag_configure("large", background=self.COLORS["secondary"], foreground="black")

    def sort_column(self, col, reverse):
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda: self.sort_column(col, not reverse))

    def show_tree_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.tree_menu.post(event.x_root, event.y_root)

    def replay_selected(self):
        selection = self.tree.selection()
        if not selection: return
        item = self.tree.item(selection[0])
        pkt_id = int(item['values'][0])
        if self.replay_packet_callback(pkt_id):
            messagebox.showinfo("✅ Success", f"Packet #{pkt_id} replayed!")
        else:
            messagebox.showerror("❌ Failed", "Only TCP/UDP packets can be replayed.")

    def show_packet_details(self, event=None):
        selection = self.tree.selection()
        if not selection: return
        item = self.tree.item(selection[0])
        pkt_id = int(item['values'][0])
        ph_data = self.get_packet_handler_data_callback()
        pkt = next((p for p in ph_data.get('packets', []) if p['id'] == pkt_id), None)
        if not pkt: return

        self.details_text.config(state='normal')
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, f"📦 PACKET #{pkt['id']} | {pkt['time']}\n", "header")
        self.details_text.insert(tk.END,
                                 f"🔗 PROTOCOL: {pkt['proto']} | SRC: {pkt['src']}:{pkt['src_port']} → DST: {pkt['dst']}:{pkt['dst_port']}\n")
        self.details_text.insert(tk.END, f"💾 PAYLOAD: {pkt['payload_type']} | Size: {pkt['payload_size']} bytes\n")
        self.details_text.insert(tk.END,
                                 f"🌎 SRC GEO: {pkt['src_geo']['city']}, {pkt['src_geo']['country']} ({pkt['src_geo']['region']})\n")
        self.details_text.insert(tk.END,
                                 f"🌎 DST GEO: {pkt['dst_geo']['city']}, {pkt['dst_geo']['country']} ({pkt['dst_geo']['region']})\n")
        if pkt['payload_preview'] and pkt['payload_preview'] != "<binary>":
            self.details_text.insert(tk.END, f"\n🔤 PAYLOAD PREVIEW: {pkt['payload_preview']}\n")
        if pkt['http_dns_info']:
            self.details_text.insert(tk.END, f"\n🌐 {pkt['http_dns_info']}\n")
        if pkt['suspicious'] or pkt['anomaly']:
            self.details_text.insert(tk.END, f"\n🚨 ALERTS:\n", "alert")
            for r in pkt['reasons']:
                self.details_text.insert(tk.END, f" • {r}\n")
        self.details_text.tag_config("header", font=("Segoe UI", 11, "bold"), foreground=self.COLORS["primary"])
        self.details_text.tag_config("alert", foreground=self.COLORS["danger"], font=("Segoe UI", 9, "bold"))
        self.details_text.config(state='disabled')

    def update_summary_tab(self):
        self.ax1.clear()
        self.ax2.clear()
        self.ax3.clear()
        self.ax4.clear()

        ph_data = self.get_packet_handler_data_callback()
        protocol_stats = ph_data.get('protocol_stats', {})
        total_packets = ph_data.get('total_packets', 0)
        suspicious_count = ph_data.get('suspicious_count', 0)
        packets = ph_data.get('packets', [])

        if protocol_stats:
            labels = list(protocol_stats.keys())
            sizes = list(protocol_stats.values())
            colors = [self.COLORS["primary"], self.COLORS["info"], self.COLORS["secondary"], self.COLORS["danger"]][:len(labels)]
            wedges, texts = self.ax1.pie(sizes, labels=None, startangle=90, colors=colors)
            self.ax1.set_title('Protocol Distribution', color=self.COLORS["text_main"], fontweight='bold', fontsize=11)
            total = sum(sizes)
            legend_labels = [f'{label} ({size / total * 100:.1f}%)' for label, size in zip(labels, sizes)]
            self.ax1.legend(wedges, legend_labels, title="Protocols", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))

        normal_count = total_packets - suspicious_count
        if total_packets > 0:
            bars = self.ax2.bar(['Normal', 'Suspicious'], [normal_count, suspicious_count],
                                color=[self.COLORS["primary"], self.COLORS["danger"]])
            self.ax2.set_title('Traffic Safety', color=self.COLORS["text_main"], fontweight='bold', fontsize=11)
            self.ax2.set_ylabel('Packets', fontweight='bold', fontsize=10)
            self.ax2.grid(axis='y', alpha=0.3)
            for bar in bars:
                height = bar.get_height()
                self.ax2.text(bar.get_x() + bar.get_width() / 2., height + 0.5, f'{int(height)}',
                              ha='center', va='bottom', fontweight='bold', fontsize=9)

        if len(packets) > 0:
            recent_packets = packets[-50:] if len(packets) > 50 else packets
            protocols = [p['proto'] for p in recent_packets]
            unique_protocols = list(set(protocols))
            colors_line = [self.COLORS["primary"], self.COLORS["info"], self.COLORS["secondary"], self.COLORS["danger"]]
            for i, proto in enumerate(unique_protocols):
                proto_indices = [j for j, p in enumerate(protocols) if p == proto]
                proto_counts = []
                running_count = 0
                for j in range(len(recent_packets)):
                    if protocols[j] == proto:
                        running_count += 1
                    proto_counts.append(running_count)
                self.ax4.plot(range(1, len(recent_packets) + 1), proto_counts,
                              label=proto, color=colors_line[i % len(colors_line)], linewidth=2)
            self.ax4.set_title('Protocol Trends (Last 50)', color=self.COLORS["text_main"], fontweight='bold', fontsize=11)
            self.ax4.set_xlabel('Packet #', fontweight='bold', fontsize=10)
            self.ax4.set_ylabel('Cumulative', fontweight='bold', fontsize=10)
            self.ax4.legend(fontsize=9)
            self.ax4.grid(alpha=0.3)

        locations, _ = self.get_geo_summary_data()
        if locations:
            sorted_locations = sorted(locations.items(), key=lambda x: x[1], reverse=True)[:5]
            countries = [item[0] for item in sorted_locations]
            counts = [item[1] for item in sorted_locations]
            bars = self.ax3.bar(countries, counts, color=self.COLORS["primary"])
            self.ax3.set_title('Top Countries', color=self.COLORS["text_main"], fontweight='bold', fontsize=11)
            self.ax3.set_ylabel('Packets', fontweight='bold', fontsize=10)
            self.ax3.tick_params(axis='x', rotation=45, labelsize=9)
            self.ax3.grid(axis='y', alpha=0.3)
            for bar in bars:
                height = bar.get_height()
                self.ax3.text(bar.get_x() + bar.get_width() / 2., height + 0.5, f'{int(height)}',
                              ha='center', va='bottom', fontweight='bold', fontsize=9)
        else:
            self.ax3.text(0.5, 0.5, 'No locations', horizontalalignment='center', verticalalignment='center',
                          transform=self.ax3.transAxes, fontsize=11, color=self.COLORS["text_main"])

        self.fig.tight_layout()
        self.canvas.draw()
        self.update_geo_summary()

    def get_geo_summary_data(self):
        ph_data = self.get_packet_handler_data_callback()
        locations = {}
        unique_ips = set()
        for pkt in ph_data.get('packets', []):
            for key in ['src', 'dst']:
                ip = pkt[key]
                geo_key = f"{key}_geo"
                geo = pkt[geo_key]
                if geo['country'] != "Local" and geo['country'] != "Unknown":
                    unique_ips.add(ip)
                    loc_key = f"{geo['country']} - {geo['city']}"
                    if loc_key not in locations:
                        locations[loc_key] = 0
                    locations[loc_key] += 1
        return locations, len(unique_ips)

    def update_geo_summary(self):
        try:
            self.geo_summary_text.config(state='normal')
            self.geo_summary_text.delete(1.0, tk.END)
            locations, total_unique_ips = self.get_geo_summary_data()
            total_packets_with_geo = sum(locations.values()) if locations else 0
            total_locations = len(locations) if locations else 0
            avg_packets_per_location = total_packets_with_geo / total_locations if total_locations > 0 else 0

            if not locations:
                self.geo_summary_text.insert(tk.END, "🔍 No external locations detected yet.\n")
                self.geo_summary_text.insert(tk.END, "▶ Start capture to populate this panel.\n")
            else:
                self.geo_summary_text.insert(tk.END, "📊 GEOIP SUMMARY\n", "header")
                self.geo_summary_text.insert(tk.END, f"IPs: {total_unique_ips} | Locations: {total_locations}\n")
                self.geo_summary_text.insert(tk.END,
                                             f"Packets: {total_packets_with_geo} | Avg: {avg_packets_per_location:.1f}\n")
                self.geo_summary_text.insert(tk.END, "TOP 5 LOCATIONS:\n", "subheader")
                sorted_locations = sorted(locations.items(), key=lambda x: x[1], reverse=True)
                for i, (loc, count) in enumerate(sorted_locations[:5]):
                    self.geo_summary_text.insert(tk.END, f"{i + 1}. {loc}: {count}\n")

            self.geo_summary_text.tag_config("header", font=("Segoe UI", 10, "bold"), foreground=self.COLORS["primary"])
            self.geo_summary_text.tag_config("subheader", font=("Segoe UI", 9, "bold"), foreground=self.COLORS["info"])
            self.geo_summary_text.config(state='disabled')
        except Exception as e:
            self.geo_summary_text.config(state='normal')
            self.geo_summary_text.delete(1.0, tk.END)
            self.geo_summary_text.insert(tk.END, f"Error: {str(e)}")
            self.geo_summary_text.config(state='disabled')

    def update_suspicious_tab(self):
        for item in self.suspicious_tree.get_children():
            self.suspicious_tree.delete(item)

        ph_data = self.get_packet_handler_data_callback()
        for pkt in ph_data.get('suspicious_packets', []):
            reason_str = "; ".join(pkt['reasons'][:2])
            self.suspicious_tree.insert("", "end", values=(
                pkt['id'], pkt['time'], pkt['src'], pkt['dst'], reason_str
            ))

    def show_suspicious_details(self, event=None):
        selection = self.suspicious_tree.selection()
        if not selection: return
        item = self.suspicious_tree.item(selection[0])
        pkt_id = int(item['values'][0])
        ph_data = self.get_packet_handler_data_callback()
        pkt = next((p for p in ph_data.get('suspicious_packets', []) if p['id'] == pkt_id), None)
        if not pkt: return

        self.suspicious_details.config(state='normal')
        self.suspicious_details.delete(1.0, tk.END)
        self.suspicious_details.insert(tk.END, f"🚨 PACKET #{pkt['id']} | {pkt['time']}\n", "header")
        self.suspicious_details.insert(tk.END,
                                       f"🔗 {pkt['proto']} | {pkt['src']}:{pkt['src_port']} → {pkt['dst']}:{pkt['dst_port']}\n")
        self.suspicious_details.insert(tk.END, f"💾 {pkt['payload_type']} | {pkt['payload_size']} bytes\n")
        self.suspicious_details.insert(tk.END, f"🌎 SRC: {pkt['src_geo']['city']}, {pkt['src_geo']['country']}\n")
        self.suspicious_details.insert(tk.END, f"🌎 DST: {pkt['dst_geo']['city']}, {pkt['dst_geo']['country']}\n")
        self.suspicious_details.insert(tk.END, "REASONS:\n", "section")
        for r in pkt['reasons']:
            self.suspicious_details.insert(tk.END, f" • {r}\n")
        self.suspicious_details.tag_config("header", font=("Segoe UI", 11, "bold"), foreground=self.COLORS["danger"])
        self.suspicious_details.tag_config("section", font=("Segoe UI", 9, "bold"))
        self.suspicious_details.config(state='disabled')

    def update_geo_tab(self):
        try:
            for item in self.geo_tree.get_children():
                self.geo_tree.delete(item)

            ph_data = self.get_packet_handler_data_callback()
            geo_locations = ph_data.get('geo_locations', [])
            for ip_data in geo_locations:
                values = (
                    ip_data['id'],
                    ip_data['ip'],
                    ip_data['country'],
                    ip_data['city'],
                    ip_data['region'],
                    f"{ip_data['lat']:.4f}" if ip_data['lat'] != 0.0 else "N/A",
                    f"{ip_data['lon']:.4f}" if ip_data['lon'] != 0.0 else "N/A"
                )
                self.geo_tree.insert("", "end", values=values)
        except Exception as e:
            print(f"Error updating geo tab: {e}")

    def sort_geo_column(self, col, reverse):
        l = [(self.geo_tree.set(k, col), k) for k in self.geo_tree.get_children('')]
        l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l):
            self.geo_tree.move(k, '', index)
        self.geo_tree.heading(col, command=lambda: self.sort_geo_column(col, not reverse))

    def run(self):
        self.root.mainloop()

    def on_closing(self):
        ph_data = self.get_packet_handler_data_callback()
        if ph_data.get('is_capturing', False):
            if messagebox.askokcancel("Quit", "Capture is running. Stop and quit?"):
                self.stop_capture_callback()
                self.root.destroy()
        else:
            self.root.destroy()