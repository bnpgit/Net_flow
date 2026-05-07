import pandas as pd
import time
from scapy.all import IP, GRE, TCP, UDP, send, Raw
import sys

# Configuration
INPUT_FILE = 'data/baseline_traffic.csv'
# These represent the Carrier's Core Routers (The "Outer" Header)
# --- Change these lines ---
CARRIER_SRC = "127.0.0.1" 
CARRIER_DST = "127.0.0.1"

# Map our services to realistic Inner IPs and Ports
SERVICE_MAP = {
    'Web_Traffic':   {'src': '192.168.1.10', 'dst': '8.8.8.8', 'sport': 54321, 'dport': 443, 'proto': TCP},
    'Video_Stream':  {'src': '192.168.1.20', 'dst': '104.16.0.1', 'sport': 51234, 'dport': 443, 'proto': TCP},
    'IoT_Telemetry': {'src': '192.168.1.30', 'dst': '52.4.5.6', 'sport': 40000, 'dport': 1883, 'proto': UDP}
}

def run_gateway():
    print("[*] Starting Carrier-Grade GRE Gateway...")
    try:
        df = pd.read_csv(INPUT_FILE)
    except FileNotFoundError:
        print("[!] Error: baseline_traffic.csv not found. Run generator.py first.")
        sys.exit(1)

    print(f"[*] Loaded {len(df)} simulated minutes. Injecting encapsulated packets...")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        # We simulate time faster for the demo (1 loop = 1 second instead of 1 minute)
        for index, row in df.iterrows():
            svc = row['service']
            vol = row['volume_mbps']
            cfg = SERVICE_MAP[svc]

            # 1. Craft the Inner Packet (The User's actual traffic)
            inner_ip = IP(src=cfg['src'], dst=cfg['dst'])
            transport = cfg['proto'](sport=cfg['sport'], dport=cfg['dport'])
            # We embed the volume data in the payload for our analyzer to catch later
            # We embed the volume and the exact TICK (timestamp) in the payload
            # NEW: Calculate the true simulated minute (Row Index // 3 services)
            true_tick = index // len(SERVICE_MAP)
            payload = Raw(load=f"SVC:{svc}|VOL:{vol}|TICK:{true_tick}")

            inner_packet = inner_ip / transport / payload

            # 2. Craft the Outer Packet (The Carrier's Tunnel)
            outer_ip = IP(src=CARRIER_SRC, dst=CARRIER_DST)
            gre_header = GRE()

            # 3. Superimpose! (Wrap the inner packet inside the GRE tunnel)
            encapsulated_packet = outer_ip / gre_header / inner_packet

            # Send it over the local loopback interface silently
            send(encapsulated_packet, verbose=False, iface="lo")
            
            # Print output so you can see it working
            print(f"[>] Encapsulated & Sent: Outer[{CARRIER_SRC}->{CARRIER_DST}] | Inner Hidden: [{svc} @ {vol} Mbps]")
            
            # Brief pause to simulate time flowing
            time.sleep(0.3) 

    except KeyboardInterrupt:
        print("\n[*] Gateway stopped by user.")

if __name__ == "__main__":
    run_gateway()