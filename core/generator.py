import pandas as pd
import numpy as np
import math
import random
from datetime import datetime, timedelta

# Configuration for 60 minutes of "Normal" traffic
SIM_MINUTES = 60
FILE_PATH = 'data/baseline_traffic.csv'

# Defining 3 Services (The "Inner 5-Tuple" targets)
SERVICES = {
    'Web_Traffic': {'base': 120, 'amp': 30, 'phase': 0},
    'Video_Stream': {'base': 400, 'amp': 150, 'phase': 1.5},
    'IoT_Telemetry': {'base': 50, 'amp': 10, 'phase': 3.1}
}

def generate_baseline():
    print("[*] Generating periodic traffic baseline...")
    start_time = datetime.now()
    rows = []

    for m in range(SIM_MINUTES):
        timestamp = start_time + timedelta(minutes=m)
        
        for name, cfg in SERVICES.items():
            # Paper Formula: F(t) = base + amp * sin(frequency * t + phase)
            # 2*pi / 60 gives one full wave cycle over our 60 minutes
            freq = (2 * math.pi) / 60
            clean_val = cfg['base'] + cfg['amp'] * math.sin(freq * m + cfg['phase'])
            
            # Add 10% Noise as per paper parameters
            noise = clean_val * 0.10 * random.uniform(-1, 1)
            volume = max(0, round(clean_val + noise, 2))
            
            rows.append({
                'timestamp': timestamp.strftime('%H:%M:%S'),
                'service': name,
                'volume_mbps': volume
            })

    df = pd.DataFrame(rows)
    df.to_csv(FILE_PATH, index=False)
    print(f"[+] Baseline saved to {FILE_PATH}")

if __name__ == "__main__":
    generate_baseline()