import pandas as pd
import numpy as np
from collections import deque
from scapy.all import sniff, IP, GRE, Raw
import sys
import warnings
from datetime import datetime

# Suppress runtime warnings from numpy (e.g., dividing by zero on empty arrays)
warnings.filterwarnings('ignore')

# --- CONFIGURATION ---
BASELINE_FILE = 'data/baseline_traffic.csv'
WINDOW_SIZE = 10  # We compare the last 10 data points (Sliding Window)
ALERT_THRESHOLD = 0.70  # If Correlation (p) drops below 0.70, flag Anomaly!
# Prevent duplicate loopback packet processing
last_seen_ticks = {'Web_Traffic': -1, 'Video_Stream': -1, 'IoT_Telemetry': -1}
# Dictionaries to hold our sliding windows for X (Live) and Y (Baseline)
live_windows = {}
base_windows = {}
baseline_data = {}
time_ticks = {} # Keeps track of simulated time per service

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

def calculate_correlation(live_q, base_q):
    """
    Implements the Pearson Correlation Coefficient from the paper:
    p_{X,Y} = E[(X - u_x)(Y - u_y)] / (sigma_x * sigma_y)
    """
    if len(live_q) < 3:
        return 1.0 # Not enough data yet, assume normal
    
    # Convert deques to numpy arrays
    X = np.array(live_q)
    Y = np.array(base_q)
    
    # Calculate standard deviations
    std_x = np.std(X)
    std_y = np.std(Y)
    
    # If standard deviation is 0 (flatline), correlation is technically undefined,
    # but in our context, if base fluctuates and live is flat (0), it's a massive anomaly.
    if std_x == 0 or std_y == 0:
        return 0.01 
        
    # Calculate the correlation matrix and grab the coefficient
    correlation_matrix = np.corrcoef(X, Y)
    p = correlation_matrix[0, 1]
    
    return p

def process_packet(packet):
    """The Fast xFlow Proxy Logic: Decapsulate, Analyze, and Log to Dashboard"""
    
    if packet.haslayer(GRE):
        inner_payload = packet[GRE].payload
        
        if inner_payload.haslayer(Raw):
            try:
                data_str = inner_payload[Raw].load.decode('utf-8', errors='ignore')
                
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
                    correlation = calculate_correlation(live_windows[svc], base_windows[svc])
                    
                    # 4. REPORTING & DASHBOARD LOGGING
                    if len(live_windows[svc]) < WINDOW_SIZE:
                        status = "\033[93m[~] CALIBRATING WINDOW...\033[0m" 
                        csv_status = "CALIBRATING"
                    else:
                        if correlation < ALERT_THRESHOLD:
                            status = "\033[91m[!] ANOMALY DETECTED\033[0m" 
                            csv_status = "ANOMALY"
                        else:
                            status = "\033[92mHEALTHY\033[0m" 
                            csv_status = "HEALTHY"
                            
                    # Write live results to the CSV for Streamlit
                    with open('data/live_results.csv', 'a') as f:
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        f.write(f"{timestamp},{svc},{live_vol},{base_vol},{correlation:.3f},{csv_status}\n")
                    
                    # Print to terminal
                    print(f"Service: {svc.ljust(15)} | Live: {str(live_vol).ljust(6)} Mbps | Base: {str(base_vol).ljust(6)} Mbps | \u03C1: {correlation:.3f} -> {status}")
                    
                    # Print to terminal
                    print(f"Service: {svc.ljust(15)} | Live: {str(live_vol).ljust(6)} Mbps | Base: {str(base_vol).ljust(6)} Mbps | \u03C1: {correlation:.3f} -> {status}")
                    
            except Exception as e:
                # If it still crashes, uncomment the print below to see the exact error
                # print(f"Debug Error: {e}") 
                pass


def run_analyzer():
    # --- NEW: Initialize a fresh CSV file every time we boot up! ---
    print("[*] Initializing fresh SOC Dashboard datastream...")
    with open('data/live_results.csv', 'w') as f:
        f.write("Time,Service,Live_Volume,Base_Volume,Correlation,Status\n")
    # ---------------------------------------------------------------

    load_baseline()
    print("[*] Analyzer active. Sniffing for GRE tunnels on 'lo' interface...")
    print("[*] Waiting for packets... (Run gateway.py in another terminal)\n")
    
    # Sniff on the local loopback interface, filter for GRE protocol (proto 47)
    # --- Change this line ---
    sniff(iface="lo", prn=process_packet, store=False)
if __name__ == "__main__":
    run_analyzer()