"""
Handles all packet capture, parsing, analysis, GeoIP, statistics, and PCAP I/O.
NO TKINTER OR GUI CODE HERE.
Communicates with UI via callbacks.
"""

import threading
import time
import os
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, send, wrpcap, rdpcap
import geoip2.database
import queue

class PacketHandler:
    def __init__(self, on_packet_callback=None, on_bandwidth_update=None):
        """
        Initialize packet handler.
        :param on_packet_callback: Function to call when new packet is processed (for UI update)
        :param on_bandwidth_update: Function to call when bandwidth stats update (for graph)
        """
        self.on_packet_callback = on_packet_callback
        self.on_bandwidth_update = on_bandwidth_update

        # State flags
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.is_capturing = False
        self.is_paused = False

        # Data storage
        self.packets = []
        self.protocol_stats = defaultdict(int)
        self.suspicious_packets = []
        self.filtered_packets = []
        self.port_scan_tracker = defaultdict(list)

        # Filters
        self.current_filter = ""
        self.current_ip_filter = ""

        # Bandwidth tracking
        self.bandwidth_data = {
            'times': [],
            'packets_per_sec': [],
            'bytes_per_sec': [],
            'last_time': time.time(),
            'last_packet_count': 0,
            'last_byte_count': 0
        }
        self.bandwidth_queue = queue.Queue()

        # GeoIP
        self.geoip_reader = None
        self.load_geoip()

    def load_geoip(self):
        """Load GeoIP database if available."""
        GEOIP_DB_PATH = "GeoLite2-City.mmdb"
        if os.path.exists(GEOIP_DB_PATH):
            try:
                self.geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
            except Exception as e:
                print(f"⚠️ GeoIP load failed: {e}")

    def get_geo_info(self, ip):
        """Get GeoIP info for an IP address."""
        if not self.geoip_reader or ip in ("127.0.0.1", "0.0.0.0"):
            return {
                "city": "Local",
                "country": "Local",
                "region": "Local",
                "lat": 0.0,
                "lon": 0.0,
                "postal_code": "",
                "timezone": ""
            }
        try:
            resp = self.geoip_reader.city(ip)
            return {
                "city": resp.city.name or "Unknown",
                "country": resp.country.name or "Unknown",
                "region": resp.subdivisions.most_specific.name or "Unknown",
                "lat": float(resp.location.latitude) if resp.location.latitude else 0.0,
                "lon": float(resp.location.longitude) if resp.location.longitude else 0.0,
                "postal_code": resp.postal.code or "",
                "timezone": resp.location.time_zone or ""
            }
        except Exception as e:
            print(f"GeoIP error for {ip}: {e}")
            return {
                "city": "Unknown",
                "country": "Unknown",
                "region": "Unknown",
                "lat": 0.0,
                "lon": 0.0,
                "postal_code": "",
                "timezone": ""
            }

    def deep_inspect_payload(self, pkt):
        """Extract detailed info from packet payload (HTTP, DNS, size, type, preview)."""
        info = {}
        layer = None
        src_port = dst_port = 0
        payload_size = 0
        payload_type = "Empty"

        if TCP in pkt:
            layer = pkt[TCP]
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            if layer.payload:
                payload_size = len(bytes(layer.payload))
        elif UDP in pkt:
            layer = pkt[UDP]
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            if layer.payload:
                payload_size = len(bytes(layer.payload))

        # Update bandwidth stats every 1 second
        current_time = time.time()
        time_diff = current_time - self.bandwidth_data['last_time']
        if time_diff >= 1.0:
            packet_diff = len(self.packets) - self.bandwidth_data['last_packet_count']
            byte_diff = payload_size + len(bytes(pkt[IP]))  # Approximate
            self.bandwidth_data['times'].append(current_time)
            self.bandwidth_data['packets_per_sec'].append(packet_diff)
            self.bandwidth_data['bytes_per_sec'].append(byte_diff)

            # Keep only last 60 seconds
            if len(self.bandwidth_data['times']) > 60:
                self.bandwidth_data['times'] = self.bandwidth_data['times'][-60:]
                self.bandwidth_data['packets_per_sec'] = self.bandwidth_data['packets_per_sec'][-60:]
                self.bandwidth_data['bytes_per_sec'] = self.bandwidth_data['bytes_per_sec'][-60:]

            self.bandwidth_data['last_time'] = current_time
            self.bandwidth_data['last_packet_count'] = len(self.packets)
            self.bandwidth_data['last_byte_count'] += byte_diff

            # Notify UI via queue (thread-safe)
            if self.on_bandwidth_update:
                self.bandwidth_queue.put({
                    'times': self.bandwidth_data['times'].copy(),
                    'packets_per_sec': self.bandwidth_data['packets_per_sec'].copy(),
                    'bytes_per_sec': self.bandwidth_data['bytes_per_sec'].copy()
                })

        # DNS Inspection
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qd:  # Query
                try:
                    qname = dns.qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode(errors='ignore')
                    info['DNS_Q'] = str(qname).strip('.')
                except:
                    info['DNS_Q'] = "DNS Query"
            elif dns.qr == 1 and dns.an:  # Response
                answers = []
                for i in range(dns.ancount):
                    a = dns.an[i]
                    if a.type == 1:  # A record
                        try:
                            ip = a.rdata
                            if isinstance(ip, bytes):
                                ip = ".".join(str(b) for b in ip)
                            answers.append(ip)
                        except:
                            pass
                if answers:
                    info['DNS_A'] = ", ".join(answers[:3])

        # HTTP Inspection
        if TCP in pkt and pkt[TCP].payload:
            payload_bytes = bytes(pkt[TCP].payload)
            try:
                payload_str = payload_bytes.decode('utf-8', errors='ignore')
                if "HTTP" in payload_str[:50]:
                    lines = payload_str.splitlines()
                    if lines:
                        first_line = lines[0].strip()
                        if len(first_line.split()) >= 2:
                            method, path = first_line.split()[0], first_line.split()[1]
                            info['HTTP'] = f"{method} {path}"
                        else:
                            info['HTTP'] = first_line[:50]
                elif dst_port == 80 or src_port == 80:
                    lines = payload_str.splitlines()
                    if lines:
                        info['HTTP'] = lines[0][:50] + "..." if len(lines[0]) > 50 else lines[0]
            except Exception as e:
                print(f"HTTP parse error: {e}")

        # Payload type and preview
        payload_preview = ""
        if layer and layer.payload:
            raw = bytes(layer.payload)
            payload_size = len(raw)
            try:
                decoded = raw.decode('ascii', errors='ignore').strip()
                if decoded and any(c.isprintable() for c in decoded):
                    payload_preview = decoded[:30]
                    payload_type = "Text"
                else:
                    payload_preview = "<binary>"
                    payload_type = "Binary"
            except:
                payload_preview = "<binary>"
                payload_type = "Binary"
        else:
            payload_type = "Empty"

        return info, src_port, dst_port, payload_preview, payload_type, payload_size

    def detect_anomalies(self, pkt, src_port, dst_port, src_ip):
        """Detect port scans or suspicious activity."""
        reasons = []
        current_time = time.time()
        self.port_scan_tracker[src_ip] = [t for t in self.port_scan_tracker[src_ip] if current_time - t[1] < 10]
        self.port_scan_tracker[src_ip].append((dst_port, current_time))
        if len(self.port_scan_tracker[src_ip]) > 5:
            recent_ports = len(self.port_scan_tracker[src_ip])
            if recent_ports > 10:
                reasons.append(f"Port scan detected ({recent_ports} ports in 10s)")

        sus_ports = {22, 23, 445, 3389, 31337, 4444, 135, 139, 1433, 1434, 5900}
        if dst_port in sus_ports:
            reasons.append(f"Suspicious port: {dst_port}")
        if TCP in pkt and len(bytes(pkt[TCP].payload)) > 1000:
            reasons.append("Large payload (>1KB)")
        return reasons

    def highlight_suspicious(self, pkt):
        """Check if packet is suspicious (for UI highlighting)."""
        reasons = []
        if TCP in pkt:
            sus_ports = {22, 23, 445, 3389, 31337, 4444, 135, 139}
            if pkt[TCP].dport in sus_ports:
                reasons.append(f"Suspicious port: {pkt[TCP].dport}")
            if len(bytes(pkt[TCP].payload)) > 1000:
                reasons.append("Large payload (>1KB)")
        return reasons

    def packet_handler(self, pkt):
        """Main callback for Scapy sniff(). Processes each packet."""
        if IP not in pkt or self.stop_event.is_set():
            return

        while self.pause_event.is_set() and not self.stop_event.is_set():
            time.sleep(0.1)
            if self.stop_event.is_set(): return

        src = pkt[IP].src
        dst = pkt[IP].dst
        proto_num = pkt[IP].proto
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, f"Other({proto_num})")

        payload_info, src_port, dst_port, payload_preview, payload_type, payload_size = self.deep_inspect_payload(pkt)
        suspicious_reasons = self.highlight_suspicious(pkt)
        is_suspicious = len(suspicious_reasons) > 0

        anomaly_reasons = self.detect_anomalies(pkt, src_port, dst_port, src)
        has_anomaly = len(anomaly_reasons) > 0
        if has_anomaly:
            suspicious_reasons.extend(anomaly_reasons)
            is_suspicious = True

        src_geo = self.get_geo_info(src)
        dst_geo = self.get_geo_info(dst)

        http_dns_info = ""
        if 'HTTP' in payload_info:
            http_dns_info = f"HTTP: {payload_info['HTTP']}"
        elif 'DNS_Q' in payload_info:
            http_dns_info = f"DNS Query: {payload_info['DNS_Q']}"
        elif 'DNS_A' in payload_info:
            http_dns_info = f"DNS Ans: {payload_info['DNS_A']}"

        packet_data = {
            'id': len(self.packets) + 1,
            'time': time.strftime("%H:%M:%S"),
            'src': src, 'dst': dst,
            'src_port': src_port, 'dst_port': dst_port,
            'payload_preview': payload_preview,
            'payload_type': payload_type,
            'payload_size': payload_size,
            'http_dns_info': http_dns_info,
            'anomaly': "⚠️" if has_anomaly else "",
            'anomaly_reasons': anomaly_reasons,
            'src_geo': src_geo, 'dst_geo': dst_geo,
            'proto': proto_name, 'info': payload_info,
            'suspicious': is_suspicious, 'reasons': suspicious_reasons,
            'raw': pkt
        }

        self.packets.append(packet_data)
        self.protocol_stats[proto_name] += 1
        if is_suspicious:
            self.suspicious_packets.append(packet_data)

        self.apply_live_filter()

        # Notify UI — MUST be called via root.after() from main thread
        if self.on_packet_callback:
            self.on_packet_callback(packet_data)

    def apply_live_filter(self):
        """Apply current text and IP filters to packets."""
        self.filtered_packets = self.packets[:]
        if self.current_filter:
            f = self.current_filter.lower()
            self.filtered_packets = [
                p for p in self.filtered_packets
                if f in p['src'].lower() or
                   f in p['dst'].lower() or
                   f in p['proto'].lower() or
                   f in str(p['src_port']) or
                   f in str(p['dst_port']) or
                   f in p['http_dns_info'].lower() or
                   f in p['payload_type'].lower()
            ]
        if self.current_ip_filter:
            ip_f = self.current_ip_filter.strip()
            self.filtered_packets = [
                p for p in self.filtered_packets
                if ip_f == p['src'] or ip_f == p['dst']
            ]

    def replay_packet(self, pkt):
        """Replay a captured packet."""
        try:
            if TCP in pkt['raw']:
                new_pkt = TCP(
                    sport=pkt['raw'][TCP].sport,
                    dport=pkt['raw'][TCP].dport,
                    seq=pkt['raw'][TCP].seq,
                    ack=pkt['raw'][TCP].ack,
                    flags=pkt['raw'][TCP].flags
                )
                if pkt['raw'][TCP].payload:
                    new_pkt = new_pkt / Raw(pkt['raw'][TCP].payload)
                send(new_pkt, verbose=0)
                return True
            elif UDP in pkt['raw']:
                new_pkt = UDP(
                    sport=pkt['raw'][UDP].sport,
                    dport=pkt['raw'][UDP].dport
                )
                if pkt['raw'][UDP].payload:
                    new_pkt = new_pkt / Raw(pkt['raw'][UDP].payload)
                send(new_pkt, verbose=0)
                return True
        except Exception as e:
            print(f"Replay failed: {e}")
        return False

    def export_pcap(self, filename, packets_to_export=None):
        """Export packets to PCAP file."""
        if packets_to_export is None:
            packets_to_export = self.packets
        if not packets_to_export:
            return False, "No packets to export!"
        try:
            raw_packets = [pkt['raw'] for pkt in packets_to_export]
            wrpcap(filename, raw_packets)
            return True, f"PCAP saved to:\n{filename}"
        except Exception as e:
            return False, f"Failed to save PCAP:\n{str(e)}"

    def import_pcap(self, filename):
        """Import packets from PCAP file."""
        try:
            imported_packets = rdpcap(filename)
            if len(imported_packets) == 0:
                return False, "No packets found in PCAP file!"

            # Clear current data
            self.packets.clear()
            self.protocol_stats.clear()
            self.suspicious_packets.clear()
            self.filtered_packets.clear()
            self.port_scan_tracker.clear()

            # Process each packet
            for i, pkt in enumerate(imported_packets):
                if IP not in pkt:
                    continue
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto_num = pkt[IP].proto
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, f"Other({proto_num})")
                payload_info, src_port, dst_port, payload_preview, payload_type, payload_size = self.process_packet_for_import(pkt)
                suspicious_reasons = self.highlight_suspicious_for_import(pkt, src_port, dst_port)
                is_suspicious = len(suspicious_reasons) > 0
                src_geo = self.get_geo_info(src)
                dst_geo = self.get_geo_info(dst)
                http_dns_info = ""
                if 'HTTP' in payload_info:
                    http_dns_info = f"HTTP: {payload_info['HTTP']}"
                elif 'DNS_Q' in payload_info:
                    http_dns_info = f"DNS Query: {payload_info['DNS_Q']}"
                elif 'DNS_A' in payload_info:
                    http_dns_info = f"DNS Ans: {payload_info['DNS_A']}"

                packet_data = {
                    'id': i + 1,
                    'time': time.strftime("%H:%M:%S"),
                    'src': src, 'dst': dst,
                    'src_port': src_port, 'dst_port': dst_port,
                    'payload_preview': payload_preview,
                    'payload_type': payload_type,
                    'payload_size': payload_size,
                    'http_dns_info': http_dns_info,
                    'anomaly': "",
                    'anomaly_reasons': [],
                    'src_geo': src_geo, 'dst_geo': dst_geo,
                    'proto': proto_name, 'info': payload_info,
                    'suspicious': is_suspicious, 'reasons': suspicious_reasons,
                    'raw': pkt
                }
                self.packets.append(packet_data)
                self.protocol_stats[proto_name] += 1
                if is_suspicious:
                    self.suspicious_packets.append(packet_data)

            self.apply_live_filter()
            return True, f"Imported {len(self.packets)} packets from:\n{filename}"

        except Exception as e:
            return False, f"Failed to import PCAP:\n{str(e)}"

    def process_packet_for_import(self, pkt):
        """Simplified packet processing for import."""
        info = {}
        src_port = dst_port = 0
        payload_size = 0
        payload_type = "Empty"
        payload_preview = ""
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            if pkt[TCP].payload:
                payload_size = len(bytes(pkt[TCP].payload))
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            if pkt[UDP].payload:
                payload_size = len(bytes(pkt[UDP].payload))
        layer = None
        if TCP in pkt:
            layer = pkt[TCP]
        elif UDP in pkt:
            layer = pkt[UDP]
        if layer and layer.payload:
            raw = bytes(layer.payload)
            payload_size = len(raw)
            try:
                decoded = raw.decode('ascii', errors='ignore').strip()
                if decoded and any(c.isprintable() for c in decoded):
                    payload_preview = decoded[:30]
                    payload_type = "Text"
                else:
                    payload_preview = "<binary>"
                    payload_type = "Binary"
            except:
                payload_preview = "<binary>"
                payload_type = "Binary"
        return info, src_port, dst_port, payload_preview, payload_type, payload_size

    def highlight_suspicious_for_import(self, pkt, src_port, dst_port):
        """Simplified suspicious detection for import."""
        reasons = []
        sus_ports = {22, 23, 445, 3389, 31337, 4444, 135, 139}
        if TCP in pkt and pkt[TCP].dport in sus_ports:
            reasons.append(f"Suspicious port: {pkt[TCP].dport}")
        if TCP in pkt and len(bytes(pkt[TCP].payload)) > 1000:
            reasons.append("Large payload (>1KB)")
        return reasons

    def get_summary_stats(self):
        """Return stats for Summary tab graphs."""
        return {
            'protocol_stats': dict(self.protocol_stats),
            'total_packets': len(self.packets),
            'suspicious_count': len(self.suspicious_packets),
            'packets': self.packets,
            'suspicious_packets': self.suspicious_packets,
            'filtered_packets': self.filtered_packets
        }

    def get_geo_summary(self):
        """Return data for GeoIP summary panel."""
        locations = {}
        unique_ips = set()
        for pkt in self.packets:
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

    def get_geo_locations(self):
        """Return unique IP locations for Geo tab."""
        unique_ips = {}
        ip_id = 1
        for pkt in self.packets:
            for ip_key in ['src', 'dst']:
                ip = pkt[ip_key]
                geo_key = f"{ip_key}_geo"
                geo = pkt[geo_key]
                if ip not in unique_ips and geo['country'] != "Local" and geo['country'] != "Unknown":
                    unique_ips[ip] = {
                        'id': ip_id,
                        'ip': ip,
                        'country': geo['country'],
                        'city': geo['city'],
                        'region': geo['region'],
                        'lat': geo['lat'],
                        'lon': geo['lon']
                    }
                    ip_id += 1
        return list(unique_ips.values())

    def clear_all(self):
        """Clear all captured data — used on Restart."""
        self.packets.clear()
        self.protocol_stats.clear()
        self.suspicious_packets.clear()
        self.filtered_packets.clear()
        self.port_scan_tracker.clear()
        self.current_filter = ""
        self.current_ip_filter = ""

    def start_capture(self):
        """Start packet capture in background thread."""
        if self.is_capturing:
            return False, "Already capturing!"
        self.stop_event.clear()
        self.pause_event.clear()
        self.is_capturing = True
        self.is_paused = False

        def sniffer_worker():
            try:
                sniff(prn=self.packet_handler, store=False, stop_filter=lambda x: self.stop_event.is_set(), filter="ip")
            except PermissionError:
                # UI must handle this via callback or flag
                pass
            except Exception as e:
                print(f"Capture error: {e}")

        self.sniffer_thread = threading.Thread(target=sniffer_worker, daemon=True)
        self.sniffer_thread.start()
        return True, ""

    def pause_resume(self):
        """Toggle pause/resume."""
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.pause_event.set()
        else:
            self.pause_event.clear()
        return self.is_paused

    def stop_capture(self):
        """Stop ongoing capture."""
        self.stop_event.set()
        self.is_capturing = False
        self.is_paused = False
        return True

    def close(self):
        """Cleanup resources."""
        if self.geoip_reader:
            self.geoip_reader.close()