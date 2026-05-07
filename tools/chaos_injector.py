import time
import random
from scapy.all import IP, GRE, TCP, UDP, send, Raw

# Target setup (Must match the loopback tunnel we configured)
CARRIER_SRC = "127.0.0.1" 
CARRIER_DST = "127.0.0.1"

def inject_chaos(service_name, fake_volume, attack_type):
    print(f"\n[\033[91m*\033[0m] INJECTING CHAOS: {attack_type} on {service_name} at {fake_volume} Mbps!")
    
    # We generate a massive random starting tick (e.g., 50000) so it doesn't 
    # accidentally match the Gateway's current tick and get dropped as a duplicate.
    start_tick = random.randint(10000, 90000)
    
    for i in range(15): 
        # Increment the tick so the Analyzer accepts all 15 packets
        current_tick = start_tick + i 
        
        inner_ip = IP(src="192.168.1.99", dst="8.8.8.8")
        
        # --- THE FIX: We added the forged |TICK: to the payload! ---
        payload = Raw(load=f"SVC:{service_name}|VOL:{fake_volume}|TICK:{current_tick}")
        
        outer_ip = IP(src=CARRIER_SRC, dst=CARRIER_DST)
        malicious_packet = outer_ip / GRE() / inner_ip / payload
        
        send(malicious_packet, verbose=False, iface="lo")
        print(f"   [>] Malicious Packet {i+1}/15 sent... (Forged Tick: {current_tick})")
        time.sleep(0.2) 
        
    print("[\033[92m+\033[0m] Attack sequence complete.")

if __name__ == "__main__":
    print("--- RED TEAM: CHAOS INJECTOR ---")
    print("1. Simulate Web_Traffic DDoS (Spike to 950 Mbps)")
    print("2. Simulate Video_Stream Failure (Drop to 0 Mbps)")
    print("--------------------------------")
    
    choice = input("Select Attack Vector (1 or 2): ")
    
    if choice == '1':
        inject_chaos('Web_Traffic', 950.0, "DDoS Attack")
    elif choice == '2':
        inject_chaos('Video_Stream', 0.0, "Total Service Failure")
    else:
        print("[!] Invalid choice. Exiting.")

if __name__ == "__main__":
    print("--- RED TEAM: CHAOS INJECTOR ---")
    print("1. Simulate Web_Traffic DDoS (Spike to 950 Mbps)")
    print("2. Simulate Video_Stream Failure (Drop to 0 Mbps)")
    print("--------------------------------")
    
    choice = input("Select Attack Vector (1 or 2): ")
    
    if choice == '1':
        inject_chaos('Web_Traffic', 950.0, "DDoS Attack")
    elif choice == '2':
        inject_chaos('Video_Stream', 0.0, "Total Service Failure")
    else:
        print("[!] Invalid choice. Exiting.")