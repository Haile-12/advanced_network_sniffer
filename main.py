"""
Main entry point. Creates PacketHandler and UI, connects them together.
Handles threading and callbacks.
"""
from datetime import time

from ui import ModernPacketSnifferUI
from packet_handler import PacketHandler
import tkinter as tk
from tkinter import messagebox
import threading

class App:
    def __init__(self):
        self.packet_handler = PacketHandler(
            on_packet_callback=self.on_new_packet,
            on_bandwidth_update=self.on_bandwidth_update
        )

        self.ui = ModernPacketSnifferUI(
            start_capture_callback=self.start_capture,
            stop_capture_callback=self.stop_capture,
            pause_resume_callback=self.pause_resume,
            restart_callback=self.restart_capture,
            export_pcap_callback=self.export_pcap,
            import_pcap_callback=self.import_pcap,
            export_log_callback=self.export_log,
            export_suspicious_callback=self.export_suspicious,
            clear_suspicious_callback=self.clear_suspicious,
            toggle_theme_callback=self.toggle_theme,
            replay_packet_callback=self.replay_selected_packet,
            on_filter_change_callback=self.on_filter_change,
            on_ip_filter_change_callback=self.on_ip_filter_change,
            get_packet_handler_data_callback=self.get_packet_handler_data
        )

    def get_packet_handler_data(self):
        """Return current state of packet handler for UI."""
        stats = self.packet_handler.get_summary_stats()
        return {
            'packets': self.packet_handler.packets,
            'filtered_packets': self.packet_handler.filtered_packets,
            'suspicious_packets': self.packet_handler.suspicious_packets,
            'protocol_stats': stats['protocol_stats'],
            'total_packets': stats['total_packets'],
            'suspicious_count': stats['suspicious_count'],
            'is_capturing': self.packet_handler.is_capturing,
            'is_paused': self.packet_handler.is_paused,
            'bandwidth_queue': self.packet_handler.bandwidth_queue,
            'geo_locations': self.packet_handler.get_geo_locations()
        }

    def on_new_packet(self, packet_data):
        """Called by PacketHandler when new packet arrives."""
        self.ui.root.after(0, self.ui.update_live_tab_realtime)

    def on_bandwidth_update(self):
        """Called by PacketHandler when bandwidth stats update."""
        # Handled inside UI animation
        pass

    # --- UI Callbacks ---
    def start_capture(self):
        success, error = self.packet_handler.start_capture()
        if not success:
            messagebox.showerror("Error", error)
            return
        self.ui.btn_start.config(state='disabled')
        self.ui.btn_pause.config(state='normal')
        self.ui.btn_stop.config(state='normal')
        self.ui.btn_restart.config(state='normal')
        # Enable stop button after thread starts
        self.ui.root.after(100, lambda: self.ui.btn_stop.config(state='normal'))

    def stop_capture(self):
        self.packet_handler.stop_capture()
        self.ui.btn_start.config(state='normal')
        self.ui.btn_pause.config(state='disabled', text="⏸ Pause")
        self.ui.btn_stop.config(state='disabled')
        self.ui.btn_restart.config(state='normal')
        self.ui.update_all_tabs()

    def pause_resume(self):
        is_paused = self.packet_handler.pause_resume()
        if is_paused:
            self.ui.btn_pause.config(text="▶ Resume")
        else:
            self.ui.btn_pause.config(text="⏸ Pause")
        self.ui.update_all_tabs()

    def restart_capture(self):
        if messagebox.askyesno("🔄 Restart",
                               "This will clear all captured data, reset the sniffer, and start new capture. Are you ready to continue?"):
            self.packet_handler.clear_all()
            self.ui.update_all_tabs()
            self.ui.status_var.set("🔄 SYSTEM RESTARTED")
            self.ui.root.after(500, self.start_capture)

    def export_pcap(self):
        filename = tk.filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            initialfile="capture.pcap"
        )
        if not filename: return
        success, message = self.packet_handler.export_pcap(filename)
        if success:
            messagebox.showinfo("✅ Success", message)
        else:
            messagebox.showerror("❌ Error", message)

    def import_pcap(self):
        filename = tk.filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")],
            title="Select PCAP file to import"
        )
        if not filename: return
        success, message = self.packet_handler.import_pcap(filename)
        if success:
            messagebox.showinfo("✅ Success", message)
            self.ui.update_all_tabs()
        else:
            messagebox.showerror("❌ Error", message)

    def export_log(self):
        filename = tk.filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not filename: return
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("=== NETWORK MONITORING DASHBOARD LOG ===\n")
                f.write(f"Generated: {time.ctime()}\n")
                stats = self.packet_handler.get_summary_stats()
                f.write(f"Total Packets: {stats['total_packets']}\n")
                f.write(f"Suspicious Packets: {len(self.packet_handler.suspicious_packets)}\n")
                for pkt in self.packet_handler.packets:
                    f.write(f"[{pkt['id']}] {pkt['time']} | {pkt['proto']}\n")
                    f.write(f"  SRC: {pkt['src']}:{pkt['src_port']} → DST: {pkt['dst']}:{pkt['dst_port']}\n")
                    f.write(f"  PAYLOAD: {pkt['payload_type']} | Size: {pkt['payload_size']} bytes\n")
                    f.write(f"  SRC GEO: {pkt['src_geo']['city']}, {pkt['src_geo']['country']}\n")
                    f.write(f"  DST GEO: {pkt['dst_geo']['city']}, {pkt['dst_geo']['country']}\n")
                    if pkt['payload_preview'] and pkt['payload_preview'] != "<binary>":
                        f.write(f"  PREVIEW: {pkt['payload_preview']}\n")
                    if pkt['http_dns_info']:
                        f.write(f"  {pkt['http_dns_info']}\n")
                    if pkt['suspicious']:
                        f.write("  🚨 ALERTS:\n")
                        for r in pkt['reasons']:
                            f.write(f"    • {r}\n")
                    f.write("-" * 60 + "\n")
            messagebox.showinfo("✅ Success", f"Log saved to:\n{filename}")
        except Exception as e:
            messagebox.showerror("❌ Error", str(e))

    def export_suspicious(self):
        if not self.packet_handler.suspicious_packets:
            messagebox.showinfo("ℹ️ Info", "No suspicious packets to export.")
            return
        filename = tk.filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="suspicious.txt"
        )
        if not filename: return
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("=== SUSPICIOUS ACTIVITY LOG ===\n")
                f.write(f"Generated: {time.ctime()}\n")
                f.write(f"Total: {len(self.packet_handler.suspicious_packets)}\n")
                for pkt in self.packet_handler.suspicious_packets:
                    f.write(f"[{pkt['id']}] {pkt['time']} | {pkt['proto']}\n")
                    f.write(f"  SRC: {pkt['src']}:{pkt['src_port']} → DST: {pkt['dst']}:{pkt['dst_port']}\n")
                    f.write(f"  PAYLOAD: {pkt['payload_type']} | Size: {pkt['payload_size']} bytes\n")
                    f.write(f"  SRC GEO: {pkt['src_geo']['city']}, {pkt['src_geo']['country']}\n")
                    f.write(f"  DST GEO: {pkt['dst_geo']['city']}, {pkt['dst_geo']['country']}\n")
                    f.write("  REASONS:\n")
                    for r in pkt['reasons']:
                        f.write(f"    • {r}\n")
                    f.write("-" * 50 + "\n")
            messagebox.showinfo("✅ Success", f"Suspicious packets saved to:\n{filename}")
        except Exception as e:
            messagebox.showerror("❌ Error", str(e))

    def clear_suspicious(self):
        if not self.packet_handler.suspicious_packets:
            messagebox.showinfo("ℹ️ Info", "No suspicious packets to clear.")
            return
        if messagebox.askyesno("🗑️ Clear", "Clear all suspicious flags?"):
            self.packet_handler.suspicious_packets.clear()
            self.ui.update_suspicious_tab()
            messagebox.showinfo("✅ Cleared", "All suspicious flags removed.")

    def toggle_theme(self):
        self.ui.toggle_theme()

    def replay_selected_packet(self, packet_id):
        """Replay packet by ID."""
        pkt = next((p for p in self.packet_handler.packets if p['id'] == packet_id), None)
        if not pkt:
            return False
        return self.packet_handler.replay_packet(pkt)

    def on_filter_change(self, filter_text):
        self.packet_handler.current_filter = filter_text
        self.packet_handler.apply_live_filter()
        self.ui.update_live_tab()

    def on_ip_filter_change(self, ip_filter_text):
        self.packet_handler.current_ip_filter = ip_filter_text
        self.packet_handler.apply_live_filter()
        self.ui.update_live_tab()

    def run(self):
        self.ui.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.ui.run()

    def on_closing(self):
        self.packet_handler.stop_capture()
        self.packet_handler.close()
        self.ui.root.destroy()

if __name__ == "__main__":
    app = App()
    app.run()