import streamlit as st
import nmap
import pandas as pd

def scan_network(target, scan_mode):
    """Scan a network using python-nmap."""
    nm = nmap.PortScanner()
    try:
        if scan_mode == "Quick Scan":
            nm.scan(hosts=target, arguments="-T4")
        elif scan_mode == "Full Scan":
            nm.scan(hosts=target, arguments="-A")
        elif scan_mode == "Ping Scan":
            nm.scan(hosts=target, arguments="-sn")
        
        return nm.all_hosts(), nm
    except Exception as e:
        return None, str(e)

def format_results(nm, hosts):
    """Format nmap results into a DataFrame."""
    data = []
    for host in hosts:
        hostname = nm[host].hostname() if 'hostname' in nm[host] else "N/A"
        state = nm[host].state()
        open_ports = []
        if 'tcp' in nm[host]:
            for port, details in nm[host]['tcp'].items():
                open_ports.append(f"{port}/{details['name']}")
        open_ports_str = ", ".join(open_ports)
        
        data.append({
            "Host": host,
            "State": state,
            "Hostname": hostname,
            "Open Ports": open_ports_str if open_ports else "None"
        })
    return pd.DataFrame(data)

# Streamlit UI
st.title("Nmap Network Scanner with python-nmap")

# Input fields
target_ip_range = st.text_input("Enter Target IP/Range (e.g., 192.168.1.0/24):", "192.168.1.0/24")
scan_mode = st.selectbox("Select Scan Mode:", ["Quick Scan", "Full Scan", "Ping Scan"])

# Start scan
if st.button("Start Scan"):
    with st.spinner("Scanning network..."):
        hosts, result = scan_network(target_ip_range, scan_mode)
        
        if hosts:
            st.success(f"Scan Complete! Found {len(hosts)} host(s).")
            results_table = format_results(result, hosts)
            st.table(results_table)  # Display results in a table
        else:
            st.error(f"An error occurred: {result}")
