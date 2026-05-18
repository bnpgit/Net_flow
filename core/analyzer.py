import pandas as pd
import json
import os
import numpy as np
from collections import deque
from scapy.all import sniff, IP, GRE, Raw ,TCP,UDP
import sys
import warnings
from datetime import datetime
from core.detection_engine import DetectionEngine
from core.flow_tracker import FlowTracker
from core.threat_detector import ThreatDetector
# Suppress runtime warnings from numpy (e.g., dividing by zero on empty arrays)
warnings.filterwarnings('ignore')

# --- CONFIGURATION ---
BASELINE_FILE = 'data/baseline_traffic.csv'
WINDOW_SIZE = 10  # We compare the last 10 data points (Sliding Window)
#ALERT_THRESHOLD = 0.70  # If Correlation (p) drops below 0.70, flag Anomaly!
# Prevent duplicate loopback packet processing
last_seen_ticks = {'Web_Traffic': -1, 'Video_Stream': -1, 'IoT_Telemetry': -1}
# Dictionaries to hold our sliding windows for X (Live) and Y (Baseline)
live_windows = {}
base_windows = {}
baseline_data = {}
time_ticks = {} # Keeps track of simulated time per service
detector = DetectionEngine()
flow_tracker = FlowTracker()
threat_detector = ThreatDetector()

# ----------------------------------------
# RESET SESSION DATA
# ----------------------------------------

with open("data/alerts.json", "w") as f:
    f.write("[]")

with open("data/live_results.csv", "w") as f:
    f.write(
        "Time,Service,Live_Volume,Base_Volume,"
        "Correlation,ZScore,Risk,Status\n"
    )


def load_baseline():
    """Loads the historical periodic data into memory."""
    print("[*] Loading historical baseline (\u0059\u0305)...")
    try:
        df = pd.read_csv(BASELINE_FILE)
        for svc in df['service'].unique():
            # Store the baseline volumes in a list
            baseline_data[svc] = df[df['service'] == svc]['volume_mbps'].tolist()
            # Initialize sliding windows
            live_windows[svc] = deque(maxlen=WINDOW_SIZE)
            base_windows[svc] = deque(maxlen=WINDOW_SIZE)
            time_ticks[svc] = 0
    except Exception as e:
        print(f"[!] Error loading baseline: {e}")
        sys.exit(1)


def process_packet(packet):
    """The Fast xFlow Proxy Logic: Decapsulate, Analyze, and Log to Dashboard"""
    
    if packet.haslayer(GRE):
        packet_size = len(packet)
        inner_payload = packet[GRE].payload
        
        src_ip = "UNKNOWN"
        dst_ip = "UNKNOWN"
        src_port = 0
        dst_port = 0
        protocol = "OTHER"

        if inner_payload.haslayer(IP):

            src_ip = inner_payload[IP].src
            dst_ip = inner_payload[IP].dst

            if inner_payload.haslayer(TCP):

                protocol = "TCP"
                src_port = inner_payload[TCP].sport
                dst_port = inner_payload[TCP].dport

            elif inner_payload.haslayer(UDP):

                protocol = "UDP"
                src_port = inner_payload[UDP].sport
                dst_port = inner_payload[UDP].dport



        if inner_payload.haslayer(Raw):
            try:
                data_str = inner_payload[Raw].load.decode('utf-8', errors='ignore')
                
                flow_stats = flow_tracker.update_flow(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                packet_size
                )

                if "SVC:" in data_str and "VOL:" in data_str and "TICK:" in data_str:
                    parts = data_str.split('|')
                    svc = parts[0].split(':')[1]
                    live_vol = float(parts[1].split(':')[1])
                    tick = int(parts[2].split(':')[1])
                    
                    # --- ANTI-ECHO DEDUPLICATION ---
                    if tick == last_seen_ticks[svc]:
                        return # Drop the packet, we already processed it!
                    last_seen_ticks[svc] = tick
                    
                    # 2. SLIDING WINDOW UPDATE
                    base_vol = baseline_data[svc][tick % len(baseline_data[svc])] 
                    
                    live_windows[svc].append(live_vol)
                    base_windows[svc].append(base_vol)
                    
                    # 3. STATISTICAL CORRELATION MATH
                    # Calculate correlation and z-score to determine the final risk classification
                    correlation = detector.calculate_correlation(live_windows[svc], base_windows[svc])
                    zscore = detector.calculate_zscore(live_vol, baseline_data[svc])

                    # Generate risk score and classify the status
                    risk = detector.calculate_risk(correlation, zscore)
                    csv_status = detector.classify(risk)

                    port_scan_detected,scan_message = (
                        threat_detector.detect_port_scan(
                            src_ip,
                            dst_port
                        )
                    )

                    if port_scan_detected:

                        risk = min(risk + 40, 100)

                        csv_status = "CRITICAL"

                        detector.push_dashboard_alert(
                            scan_message,
                            src_ip,
                            dst_ip,
                            risk,
                            "CRITICAL"
                        )
                        
                        
                        detector.push_active_threat(
                                "PORT_SCAN",
                                src_ip,
                                dst_ip,
                                risk,
                                "CRITICAL"
                            )

                        print(
                            f"\033[91m"
                            f"[{scan_message}] "
                            f"{src_ip} scanning multiple ports!"
                            f"\033[0m"
                        )

                    
                    # 4. REPORTING & DASHBOARD LOGGING
                    if len(live_windows[svc]) < WINDOW_SIZE:
                        status = "\033[93m[~] CALIBRATING WINDOW...\033[0m"
                        csv_status = "CALIBRATING"
                        risk = 0
                    else:
                        if csv_status == "CRITICAL":
                            status = "\033[91m[!] CRITICAL ANOMALY\033[0m"
                        elif csv_status == "WARNING":
                            status = "\033[93m[!] WARNING\033[0m"
                        else:
                            status = "\033[92mHEALTHY\033[0m"

                        detector.log_alert(
                        svc,
                        correlation,
                        zscore,
                        risk,
                        csv_status
                        )

                        detector.push_dashboard_alert(
                            svc,
                            src_ip,
                            dst_ip,
                            risk,
                            csv_status
                        )

                            
                    # Write live results to the CSV for Streamlit
                    with open('data/live_results.csv', 'a') as f:
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        f.write(f"{timestamp},{svc},{live_vol},{base_vol},{correlation:.3f},{zscore:.2f},{risk},{csv_status}\n")
                    
                    # Print to terminal
                    #print(f"Service: {svc.ljust(15)} | Live: {str(live_vol).ljust(6)} Mbps | Base: {str(base_vol).ljust(6)} Mbps | \u03C1: {correlation:.3f} -> {status}")
                    
                    # Print to terminal
                    #print(f"Service: {svc.ljust(15)} | Live: {str(live_vol).ljust(6)} Mbps | Base: {str(base_vol).ljust(6)} Mbps | \u03C1: {correlation:.3f} -> {status}")
                    print(f"Service: {svc.ljust(15)} | Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | PPS: {flow_stats['packets_per_second']} | BPS: {flow_stats['bytes_per_second']} | Risk: {risk}/100 -> {status}")
                    flow_tracker.cleanup_expired_flows()
            except Exception as e:
                # If it still crashes, uncomment the print below to see the exact error
                # print(f"Debug Error: {e}") 
                pass


def run_analyzer():
    # --- NEW: Initialize a fresh CSV file every time we boot up! ---
    print("[*] Initializing fresh SOC Dashboard datastream...")
    with open('data/live_results.csv', 'w') as f:
        f.write(
        "Time,Service,Live_Volume,Base_Volume,"
        "Correlation,ZScore,Risk,Status\n"
    )
    # ---------------------------------------------------------------

    load_baseline()
    print("[*] Analyzer active. Sniffing for GRE tunnels on 'lo' interface...")
    print("[*] Waiting for packets... (Run gateway.py in another terminal)\n")
    
    # Sniff on the local loopback interface, filter for GRE protocol (proto 47)
    # --- Change this line ---
    sniff(iface="lo", prn=process_packet, store=False)
if __name__ == "__main__":
    run_analyzer()
