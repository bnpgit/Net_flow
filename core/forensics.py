import math
from collections import Counter
from scapy.all import PcapReader, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw
import pandas as pd
import re

class ForensicAnalyzer:
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        
        # New Analyst Memory Structures
        self.dns_queries = set()
        self.connections = []
        self.suspicious_alerts = []

    def calculate_entropy(self, payload):
        if not payload: return 0.0
        entropy = 0
        length = len(payload)
        occurrences = Counter(payload)
        for count in occurrences.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return float(entropy)

    def is_suspicious_port(self, port):
        """Flags common malware backdoor and administrative ports."""
        dangerous_ports = [4444, 1337, 3389, 22, 23, 8080, 6667] # Meterpreter, RDP, SSH, Telnet, IRC
        return port in dangerous_ports

    def is_suspicious_domain(self, domain):
        """Flags randomly generated domains or suspicious Top Level Domains."""
        suspicious_tlds = ['.top', '.xyz', '.cc', '.pw', '.su']
        return any(domain.endswith(tld) for tld in suspicious_tlds)

    def run_analysis(self, progress_callback=None):
        from scapy.all import ICMP, ARP, DHCP, Ether
        from datetime import datetime
        from collections import defaultdict
        import re
        
        packet_count = 0
        seen_entropy_flows = set()
        seen_port_flows = set()
        ip_to_domain = {}
        
        self.sessions = {}
        self.timeline = []
        self.protocol_hierarchy = {}
        
        # --- NEW: ADVANCED HEURISTIC TRACKERS ---
        self.http_traffic = []         # Stores HTTP URIs, Hosts, and User-Agents
        syn_counts = defaultdict(int)  # Tracks SYN packets for DoS detection
        arp_table = defaultdict(set)   # Tracks MAC/IP pairs for MITM detection

        def guess_file_type(raw_bytes):
            if raw_bytes.startswith(b'MZ'): return "Windows Executable (EXE/DLL) ⚠️"
            if raw_bytes.startswith(b'PK\x03\x04'): return "ZIP Archive / DOCX"
            if raw_bytes.startswith(b'\x7fELF'): return "Linux Executable (ELF) ⚠️"
            if raw_bytes.startswith(b'%PDF'): return "PDF Document"
            if raw_bytes.startswith(b'HTTP') or b'GET /' in raw_bytes[:10] or b'POST /' in raw_bytes[:10]: return "HTTP Web Traffic"
            if raw_bytes.startswith(b'\xff\xd8\xff'): return "JPEG Image"
            if raw_bytes.startswith(b'SSH-'): return "SSH Encrypted Protocol"
            return "Unknown Binary / Encoded Data"

        with PcapReader(self.pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                packet_count += 1
                if progress_callback and packet_count % 500 == 0:
                    progress_callback(packet_count)
                
                layer_path = []
                current_layer = pkt
                while current_layer:
                    layer_path.append(current_layer.name)
                    current_layer = current_layer.payload if hasattr(current_layer, 'payload') and current_layer.payload.name != 'NoPayload' else None
                
                path_str = " > ".join(layer_path)
                self.protocol_hierarchy[path_str] = self.protocol_hierarchy.get(path_str, 0) + 1

                # 1. DNS & ADVANCED EXFILTRATION (DNS Tunneling)
                if pkt.haslayer(DNS):
                    if pkt.haslayer(DNSQR):
                        try:
                            raw_domain = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                            clean_domain = re.sub(r'[^a-zA-Z0-9.-]', '', raw_domain)
                            if len(clean_domain) > 3: 
                                self.dns_queries.add(clean_domain)
                                # DNS Tunneling Heuristic: Abnormally long subdomains
                                if len(clean_domain) > 55:
                                    self.suspicious_alerts.append(f"📡 DNS Tunneling / Exfil Alert: Exceptionally long domain -> {clean_domain}")
                        except: pass 
                    if pkt.haslayer(DNSRR):
                        try:
                            for i in range(pkt[DNS].ancount):
                                rr = pkt[DNS].an[i]
                                if rr.type == 1:
                                    ip_to_domain[rr.rdata] = re.sub(r'[^a-zA-Z0-9.-]', '', rr.rrname.decode('utf-8', errors='ignore').rstrip('.'))
                        except: pass

                # 2. ARP SPOOFING / MITM DETECTION
                if ARP in pkt and pkt[ARP].op == 2: # 'op=2' is an ARP Reply
                    arp_table[pkt[ARP].psrc].add(pkt[ARP].hwsrc)
                    
                # 3. ADVANCED PROTOCOL DETECTION & DoS TRACKING
                proto_label = "Other"
                src_ip, dst_ip, src_p, dst_p = "N/A", "N/A", 0, 0
                timeline_info = "Data Transfer"

                if IP in pkt:
                    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
                    if TCP in pkt:
                        proto_label, src_p, dst_p = "TCP", pkt[TCP].sport, pkt[TCP].dport
                        # SYN Flood / DoS Detection Heuristic
                        if pkt[TCP].flags == 'S': 
                            syn_counts[src_ip] += 1
                    elif UDP in pkt:
                        proto_label, src_p, dst_p = "UDP", pkt[UDP].sport, pkt[UDP].dport
                    elif ICMP in pkt:
                        proto_label = "ICMP"
                elif ARP in pkt:
                    proto_label, src_ip, dst_ip = "ARP", pkt[ARP].psrc, pkt[ARP].pdst
                    timeline_info = "ARP Broadcast / Resolution"

                if pkt.haslayer(DHCP):
                    proto_label = "DHCP"
                    timeline_info = "DHCP Assignment"

                if src_ip == "N/A": continue

                session_key = tuple(sorted([(src_ip, src_p), (dst_ip, dst_p)])) + (proto_label,)
                if session_key not in self.sessions: self.sessions[session_key] = []

                # 4. PAYLOAD, ENTROPY & HTTP PARSING
                entropy = 0.0
                file_type = "No Payload"
                raw_hex = ""
                
                if Raw in pkt:
                    payload = pkt[Raw].load
                    if len(payload) > 10:
                        entropy = self.calculate_entropy(payload)
                        file_type = guess_file_type(payload)
                        raw_hex = payload[:500].hex() 
                        
                        # --- NEW: Deep HTTP Extraction ---
                        payload_str = payload.decode('utf-8', errors='ignore')
                        if payload_str.startswith(('GET ', 'POST ', 'PUT ')):
                            lines = payload_str.split('\r\n')
                            method_uri = lines[0]
                            host = next((l.split(': ')[1] for l in lines if l.startswith('Host: ')), 'Unknown')
                            ua = next((l.split(': ')[1] for l in lines if l.startswith('User-Agent: ')), 'Unknown')
                            
                            self.http_traffic.append({
                                'Source': src_ip, 'Destination': dst_ip,
                                'Request': method_uri, 'Host': host, 'User-Agent': ua
                            })
                            timeline_info = f"HTTP {method_uri}"
                        elif payload_str.startswith('HTTP/'):
                            res_line = payload_str.split('\r\n')[0]
                            timeline_info = f"HTTP Response: {res_line}"
                            
                        self.sessions[session_key].append(f"[{src_ip} -> {dst_ip}]\n{repr(payload)}")
                        
                        if entropy > 7.5:
                            flow_key = tuple(sorted([src_ip, dst_ip]))
                            if flow_key not in seen_entropy_flows:
                                self.suspicious_alerts.append(f"🔐 Encrypted Exfiltration: {src_ip} ↔ {dst_ip} (High Entropy)")
                                seen_entropy_flows.add(flow_key)

                if self.is_suspicious_port(dst_p):
                    if (dst_ip, dst_p) not in seen_port_flows:
                        self.suspicious_alerts.append(f"🚪 Malicious Port: {dst_ip}:{dst_p}")
                        seen_port_flows.add((dst_ip, dst_p))

                # Append to Timeline
                timestamp_str = datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                if Raw in pkt or proto_label in ["DNS", "DHCP", "ARP"]:
                    self.timeline.append({
                        'Time': timestamp_str, 'Source': src_ip, 'Destination': dst_ip,
                        'Protocol': proto_label, 'Info': timeline_info, 'File Type': file_type
                    })

                self.connections.append({
                    'Source': src_ip, 'Destination': dst_ip, 
                    'Protocol': proto_label, 'Port': dst_p, 'Entropy': entropy,
                    'File_Type': file_type, 'Raw_Hex': raw_hex
                })
        
        # --- NEW: Post-Processing Heuristics ---
        # MITM Check
        for ip, macs in arp_table.items():
            if len(macs) > 1:
                self.suspicious_alerts.append(f"🎭 MITM / ARP Spoofing: IP {ip} is claiming multiple MAC addresses {macs}!")
                
        # DoS Check
        for ip, count in syn_counts.items():
            if count > 100:  # If an IP sends more than 100 unanswered SYNs
                self.suspicious_alerts.append(f"💥 DoS Attack (SYN Flood): {ip} generated {count} SYN requests!")

        return {
            "total_packets": packet_count, "dns_domains": list(self.dns_queries),
            "alerts": list(set(self.suspicious_alerts)), "connections": pd.DataFrame(self.connections),
            "ip_to_domain": ip_to_domain, "sessions": self.sessions,
            "timeline": pd.DataFrame(self.timeline), "hierarchy": self.protocol_hierarchy,
            "http": pd.DataFrame(self.http_traffic) # Pass HTTP data to UI
        }