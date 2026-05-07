import streamlit as st
import pandas as pd
import time
import os
import numpy as np
from core.forensics import ForensicAnalyzer
import streamlit.components.v1 as components
from pyvis.network import Network
import plotly.express as px

# --- Page Configuration ---
st.set_page_config(page_title="Granular-Flow SOC", layout="wide", initial_sidebar_state="expanded")

# --- Sidebar Navigation ---
st.sidebar.title("🛡️ Command Center")
app_mode = st.sidebar.radio("Select Module:", ["🔴 Live SOC Dashboard", "🔬 Forensic Lab"])
st.sidebar.markdown("---")

# ==========================================
# MODULE 1: THE LIVE SOC DASHBOARD
# ==========================================
if app_mode == "🔴 Live SOC Dashboard":
    st.title("🛡️ Live Network Telemetry")
    st.markdown("Real-time Decapsulation and Anomaly Detection via Pearson Correlation")
    
    DATA_FILE = 'data/live_results.csv'
    
    metric_row = st.columns(3)
    chart_row = st.columns(1)
    alert_box = st.empty()

    def load_data():
        try:
            df = pd.read_csv(DATA_FILE)
            return df.tail(100) 
        except Exception:
            return pd.DataFrame()

    # The Live Update Loop (Only runs in this mode!)
    while True:
        df = load_data()
        
        if not df.empty:
            services = ['Web_Traffic', 'Video_Stream', 'IoT_Telemetry']
            for i, svc in enumerate(services):
                svc_data = df[df['Service'] == svc]
                if not svc_data.empty:
                    latest = svc_data.iloc[-1]
                    color = "normal" if latest['Status'] == "HEALTHY" else "inverse"
                    with metric_row[i]:
                        st.metric(
                            label=f"📡 {svc.replace('_', ' ')} (\u03C1)", 
                            value=f"{latest['Correlation']}", 
                            delta=latest['Status'],
                            delta_color=color
                        )

            chart_data = df.pivot_table(index='Time', columns='Service', values='Live_Volume', aggfunc=np.mean)
            with chart_row[0]:
                st.line_chart(chart_data, height=350, use_container_width=True)
                
            anomalies = df[df['Status'] == 'ANOMALY']
            if not anomalies.empty:
                alert_box.error(f"🚨 ACTIVE ANOMALY DETECTED: {anomalies.iloc[-1]['Service']} correlation dropped to {anomalies.iloc[-1]['Correlation']}!")
            else:
                alert_box.success("✅ Network Traffic is Stable and Healthy.")
                
        time.sleep(1)
        st.rerun()

# ==========================================
# MODULE 2: THE FORENSIC LAB
# ==========================================
elif app_mode == "🔬 Forensic Lab":
    st.title("🔬 Deep Packet Inspection Lab")
    st.markdown("Upload historical network captures (.pcap) for advanced heuristic analysis and threat hunting.")
    
    uploaded_file = st.file_uploader("Upload PCAP File", type=['pcap', 'pcapng'])

    if uploaded_file:
        temp_path = os.path.join("data", "upload.pcap")
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # --- 1. SESSION STATE OPTIMIZATION ---
        # Only run the heavy analyzer if this is a NEW file!
        if "report" not in st.session_state or st.session_state.get("file_name") != uploaded_file.name:
            st.sidebar.subheader("Engine Status")
            status_text = st.sidebar.empty() 
            def update_ui(count):
                status_text.code(f"⚙️ Processed {count:,} packets...")

            with st.spinner("Executing Deep Packet Inspection & Heuristic Analysis..."):
                analyzer = ForensicAnalyzer(temp_path)
                report = analyzer.run_analysis(progress_callback=update_ui)
                
                # Save the results into the server's RAM
                st.session_state.report = report
                st.session_state.file_name = uploaded_file.name
                status_text.success(f"✅ Analysis Complete! Total Packets: {report['total_packets']:,}")
        else:
            # If the file is already processed, just instantly load it from RAM
            report = st.session_state.report

        # Build the Report UI
        st.markdown("---")
        st.header("📑 Automated Analyst Report")
        
        # --- THE 5-TAB SOC DASHBOARD ---
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "🚨 Master IOCs", 
            "📊 Master Profile", 
            "⏱️ Event Timeline", 
            "📈 Protocol Hierarchy",
            "🕸️ Map & Deep Dive"
        ])
        
        # ==========================================
        # TAB 1: MASTER IOCs (Threats, Exfil, HTTP)
        # ==========================================
        with tab1:
            st.subheader("Indicators of Compromise (IOCs)")
            st.write("Advanced heuristic engine tracking Data Exfiltration, DoS, MITM, and Application-Layer IOCs.")
            
            # --- SECTION A: CRITICAL ALERTS ---
            st.markdown("### 🛑 Critical Heuristic Alerts")
            if report['alerts']:
                for alert in report['alerts']:
                    # Color code the alerts based on the emoji we assigned in the backend!
                    if "💥" in alert or "🎭" in alert:
                        st.error(f"**[CRITICAL THREAT]** {alert}")
                    elif "📡" in alert or "🔐" in alert:
                        st.warning(f"**[EXFILTRATION]** {alert}")
                    else:
                        st.info(f"**[SUSPICIOUS]** {alert}")
            else:
                st.success("✅ No heuristic threat indicators triggered.")
                
            st.markdown("---")
            
            # --- SECTION B: HTTP RESOURCE EXTRACTION ---
            st.markdown("### 🌐 HTTP Application Resources")
            st.write("Files requested, Host headers, and User-Agents extracted from unencrypted web traffic.")
            
            http_df = report.get('http', pd.DataFrame())
            if not http_df.empty:
                # Deduplicate so we don't see 100 identical GET requests
                http_summary = http_df.drop_duplicates()
                st.dataframe(http_summary, use_container_width=True, hide_index=True)
            else:
                st.info("No unencrypted HTTP Application requests found in this capture.")
                
            st.markdown("---")
            
            # --- SECTION C: SUSPICIOUS DNS DOMAINS ---
            st.markdown("### 📓 Extracted DNS Queries")
            if report['dns_domains']:
                st.dataframe(pd.DataFrame(report['dns_domains'], columns=["Queried Domains"]), use_container_width=True, hide_index=True)
            else:
                st.info("No DNS traffic found in this capture.")
        # ==========================================
        # TAB 2: UNIFIED IP PROFILE & DRILL-DOWN
        # ==========================================
        with tab2:
            st.subheader("Master IP Profile")
            st.markdown("A unified view of every host in the capture. No duplicate ports.")
            
            df = report['connections']
            ip_mapping = report.get('ip_to_domain', {})
            
            if not df.empty:
                summary = df.groupby('Destination').agg({
                    'Protocol': lambda x: ", ".join(set(x)),
                    'Port': lambda x: ", ".join(set(str(p) for p in x if p != 0)),
                    'Source': 'count'
                }).reset_index()

                summary.columns = ['IP Address', 'Protocols', 'Ports Used', 'Packets Received']
                summary['Resolved Domain'] = summary['IP Address'].map(lambda x: ip_mapping.get(x, "N/A"))
                summary = summary[['IP Address', 'Resolved Domain', 'Protocols', 'Ports Used', 'Packets Received']].sort_values('Packets Received', ascending=False)
                
                st.dataframe(summary, use_container_width=True, hide_index=True)

                st.markdown("---")
                st.subheader("🔍 IP Drill-Down (Connection Tree)")
                selected_ip = st.selectbox("Select IP to Drill Down", options=summary['IP Address'].tolist(), format_func=lambda x: f"{x} ({ip_mapping.get(x, 'N/A')})")
                
                if selected_ip:
                    inbound = df[df['Destination'] == selected_ip][['Source', 'Protocol', 'Port']].rename(columns={'Source': 'Peer IP'})
                    inbound['Direction'] = '📥 Inbound (Received)'
                    
                    outbound = df[df['Source'] == selected_ip][['Destination', 'Protocol', 'Port']].rename(columns={'Destination': 'Peer IP'})
                    outbound['Direction'] = '📤 Outbound (Sent)'
                    
                    combined_peers = pd.concat([inbound, outbound])
                    if not combined_peers.empty:
                        peer_summary = combined_peers.groupby(['Peer IP', 'Direction']).size().reset_index(name='Packets Exchanged')
                        peer_summary['Peer Domain'] = peer_summary['Peer IP'].map(lambda x: ip_mapping.get(x, "N/A"))
                        peer_summary = peer_summary[['Peer IP', 'Peer Domain', 'Direction', 'Packets Exchanged']].sort_values('Packets Exchanged', ascending=False)
                        st.dataframe(peer_summary, use_container_width=True, hide_index=True)
                    else:
                        st.info("No detailed peer data found for this IP.")

        # ==========================================
        # TAB 3: CHRONOLOGICAL EVENT TIMELINE
        # ==========================================
        with tab3:
            st.subheader("⏱️ Chronological Event Timeline")
            st.write("A Wireshark-style flow graph showing who requested what, and server response codes.")
            
            timeline_df = report.get('timeline', pd.DataFrame())
            if not timeline_df.empty:
                timeline_df['Src Domain'] = timeline_df['Source'].map(lambda x: ip_mapping.get(x, ""))
                timeline_df['Dst Domain'] = timeline_df['Destination'].map(lambda x: ip_mapping.get(x, ""))
                timeline_df = timeline_df[['Time', 'Source', 'Src Domain', 'Destination', 'Dst Domain', 'Protocol', 'Info', 'File Type']]
                st.dataframe(timeline_df, use_container_width=True, hide_index=True, height=600)
            else:
                st.info("No timeline data could be extracted.")

        # ==========================================
        # TAB 4: PROTOCOL HIERARCHY (NATIVE STREAMLIT)
        # ==========================================
        with tab4:
            st.subheader("📈 Protocol Hierarchy Breakdown")
            st.write("Visualizing exactly how packets are encapsulated in this capture.")
            
            hierarchy_dict = report.get('hierarchy', {})
            if hierarchy_dict:
                h_data = []
                for path, count in hierarchy_dict.items():
                    layers = path.split(' > ')
                    h_data.append({'Path': path, 'Count': count, 'Top Layer': layers[-1]})
                
                h_df = pd.DataFrame(h_data).sort_values(by="Count", ascending=False)
                chart_data = h_df.set_index('Path')['Count'].head(15)
                
                st.bar_chart(chart_data, use_container_width=True)
                
                with st.expander("View Raw Protocol Hierarchy Data"):
                    st.dataframe(h_df, use_container_width=True, hide_index=True)

        # ==========================================
        # TAB 5: MAP AND CYBERCHEF TARGET INSPECTOR
        # ==========================================
        with tab5:
            st.subheader("Interactive Hub-and-Spoke Flow Map")
            
            df = report['connections']
            if not df.empty:
                malicious_ports = [4444, 1337, 3389, 22, 23, 8080, 6667]
                malicious_flows = df[(df['Entropy'] > 7.5) | (df['Port'].isin(malicious_ports))]
                malicious_ips = set(malicious_flows['Source']).union(set(malicious_flows['Destination']))

                col1, col2 = st.columns(2)
                with col1: show_safe = st.checkbox("🟢 Show Safe Connections", value=True)
                with col2: show_domains = st.checkbox("🌐 Display Domain Names", value=False)

                top_flows = df.groupby(['Source', 'Destination']).size().reset_index(name='Packet Count')
                top_flows = top_flows.sort_values(by='Packet Count', ascending=False).head(150)

                all_ips = pd.concat([top_flows['Source'], top_flows['Destination']])
                hub_ip = all_ips.mode()[0]
                unique_ips = all_ips.unique()

                ip_stats = {}
                for ip in unique_ips:
                    sent_data = df[df['Source'] == ip]
                    recv_data = df[df['Destination'] == ip]
                    all_data = pd.concat([sent_data, recv_data])
                    protocols = ", ".join(all_data['Protocol'].astype(str).unique())
                    ports = ", ".join([str(p) for p in all_data['Port'].unique() if p != 0])
                    ip_stats[ip] = {
                        'domain': ip_mapping.get(ip, 'Unknown'),
                        'protocols': protocols,
                        'ports': ports if ports else "N/A",
                        'total': len(all_data)
                    }

                net = Network(height='500px', width='100%', bgcolor='#0E1117', font_color='white')
                net.set_options('{"physics": {"barnesHut": {"gravitationalConstant": -50000}, "stabilization": {"iterations": 200}}}')

                nodes_added = set()
                for _, row in top_flows.iterrows():
                    src = row['Source']
                    dst = row['Destination']
                    spoke_ip = src if dst == hub_ip else dst
                    is_malicious = spoke_ip in malicious_ips

                    if not show_safe and not is_malicious and spoke_ip != hub_ip: continue 

                    def add_smart_node(ip):
                        if ip not in nodes_added:
                            color = '#FF4B4B' if ip == hub_ip else ('#FFA500' if ip in malicious_ips else '#00CC66')
                            label = ip_mapping.get(ip, ip) if show_domains else ip
                            stats = ip_stats[ip]
                            tooltip = f"IP: {ip}\nDomain: {stats['domain']}\nTotal: {stats['total']} pkts"
                            net.add_node(ip, label=label, title=tooltip, color=color)
                            nodes_added.add(ip)

                    add_smart_node(src)
                    add_smart_node(dst)
                    net.add_edge(src, dst, color='#FF4B4B' if is_malicious else '#444444')

                try:
                    net.save_graph('network_map.html')
                    HtmlFile = open('network_map.html', 'r', encoding='utf-8')
                    components.html(HtmlFile.read(), height=520)
                except Exception as e:
                    st.error(f"Could not render map: {e}")

                st.markdown("---")
                st.subheader("🕵️ Target Inspector & Payload Decoder")
                st.write("Analyze raw payloads, detect file types, extract plaintext, or export to CyberChef.")
                
                target_ip = st.selectbox("Select Target IP", options=unique_ips, format_func=lambda x: f"{x} ({ip_mapping.get(x, 'Unknown Domain')})")
                
                if target_ip:
                    target_traffic = df[((df['Source'] == target_ip) | (df['Destination'] == target_ip)) & (df['Raw_Hex'] != "")]
                    
                    if target_traffic.empty:
                        st.info("No raw application data found.")
                    else:
                        st.metric("Payloads Extracted", len(target_traffic))
                        import string
                        import urllib.parse
                        
                        def extract_strings(hex_data):
                            try:
                                raw_bytes = bytes.fromhex(hex_data)
                                printable = "".join(chr(b) if chr(b) in string.printable else '.' for b in raw_bytes)
                                return "\n".join([s for s in printable.split('.') if len(s) > 4])
                            except: return "Could not decode."

                        for index, row in target_traffic.head(15).iterrows(): 
                            direction = "📤 Sent" if row['Source'] == target_ip else "📥 Received"
                            ftype = row['File_Type']
                            type_icon = "⚠️" if "Executable" in ftype else "📄"
                            
                            with st.expander(f"{direction} | {type_icon} {ftype} | Port: {row['Port']} | Entropy: {row['Entropy']:.2f}"):
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.markdown("**Raw Hex Dump**")
                                    st.code(row['Raw_Hex'], language='bash')
                                    cc_recipe = '[{"op":"From Hex","args":["Auto"]}]'
                                    cc_url = f"https://gchq.github.io/CyberChef/#recipe={urllib.parse.quote(cc_recipe)}&input={urllib.parse.quote(row['Raw_Hex'])}"
                                    st.markdown(f"[**🧙‍♂️ Send to CyberChef for Deep Decoding**]({cc_url})")
                                with col2:
                                    st.markdown("**Extracted Plaintext (Strings)**")
                                    plaintext = extract_strings(row['Raw_Hex'])
                                    if plaintext.strip(): st.code(plaintext, language='text')
                                    else: st.write("*No readable text found.*")