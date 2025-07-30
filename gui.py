import subprocess
import platform
import threading
import queue
import socket
import tkinter as tk
from tkinter import ttk, messagebox
import networkx as nx
import matplotlib.pyplot as plt

# Vulnerable port dictionary
vulnerable_ports = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 143: "IMAP", 445: "SMB", 3389: "RDP"
}

common_ports = [21, 22, 23, 25, 80, 139, 443, 445, 3389, 8080]

def ping_ip(ip, q):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]

    try:
        subprocess.check_output(command, stderr=subprocess.DEVNULL)
        q.put((ip, True))
    except subprocess.CalledProcessError:
        q.put((ip, False))

def scan_ports(ip, ports=common_ports):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception:
            continue
    return open_ports

def icmp_scan_network(ip_prefix, start=1, end=24, ports_to_scan=None):
    if ports_to_scan is None:
        ports_to_scan = common_ports

    q = queue.Queue()
    threads = []
    for i in range(start, end + 1):
        ip = f"{ip_prefix}.{i}"
        t = threading.Thread(target=ping_ip, args=(ip, q))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    alive_hosts = []
    while not q.empty():
        ip, status = q.get()
        if status:
            alive_hosts.append(ip)

    scanned_data = {}
    for host in alive_hosts:
        ports = scan_ports(host, ports=ports_to_scan)
        scanned_data[host] = ports

    return scanned_data

def visualize_topology(scanned_data, gateway_ip, output_file='network_topology.pdf'):
    G = nx.Graph()
    G.add_node(gateway_ip, label="Gateway", color="#ff6666", size=2000, shape='s')  # Square

    for ip, ports in scanned_data.items():
        if ip != gateway_ip:
            label = f"{ip}\nPorts: {', '.join(map(str, ports)) if ports else 'None'}"
            G.add_node(ip, label=label, color="#99ccff", size=1000, shape='o')
            G.add_edge(gateway_ip, ip, weight=1.0)

    pos = nx.spring_layout(G, seed=42)

    node_colors = [G.nodes[n].get('color', '#cccccc') for n in G.nodes]
    node_sizes = [G.nodes[n].get('size', 1000) for n in G.nodes]
    node_labels = {n: G.nodes[n].get('label', n) for n in G.nodes}

    plt.figure(figsize=(12, 10))
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, edgecolors='black', linewidths=1.5)
    nx.draw_networkx_edges(G, pos, edge_color='#999999', style='dashed', width=2)
    nx.draw_networkx_labels(G, pos, labels=node_labels, font_size=8)

    plt.title("🔍 ICMP & Port Scan-Based Network Topology", fontsize=14, fontweight='bold')
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(output_file, format='pdf')
    plt.close()

    messagebox.showinfo("Scan Complete", f"Network topology saved as {output_file}")

# GUI implementation
def start_scan():
    subnet = subnet_entry.get().strip()
    gateway = gateway_entry.get().strip()

    if not subnet or not gateway:
        messagebox.showerror("Input Error", "Please enter both Subnet and Gateway IP.")
        return

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"[+] Scanning {subnet}.1 to {subnet}.24...\n")

    def run_scan():
        scanned = icmp_scan_network(subnet)
        result_text.insert(tk.END, f"\n[+] Active Hosts and Open Ports:\n")
        for host, ports in scanned.items():
            result_text.insert(tk.END, f" - {host}\n")
            if ports:
                for port in ports:
                    service = vulnerable_ports.get(port, "Unknown")
                    vuln = " ⚠ Vulnerable" if port in vulnerable_ports else ""
                    result_text.insert(tk.END, f"    Port {port} [{service}]{vuln}\n")
            else:
                result_text.insert(tk.END, "    No open ports detected.\n")
        visualize_topology(scanned, gateway)

    threading.Thread(target=run_scan).start()

# Set up GUI window
root = tk.Tk()
root.title("ICMP and Port Scanner GUI")
root.geometry("700x500")

frame = ttk.Frame(root, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

ttk.Label(frame, text="Subnet Prefix (e.g., 192.168.1):").grid(row=0, column=0, sticky=tk.W)
subnet_entry = ttk.Entry(frame, width=30)
subnet_entry.grid(row=0, column=1, pady=5)

ttk.Label(frame, text="Gateway IP (e.g., 192.168.1.1):").grid(row=1, column=0, sticky=tk.W)
gateway_entry = ttk.Entry(frame, width=30)
gateway_entry.grid(row=1, column=1, pady=5)

scan_button = ttk.Button(frame, text="Start Scan", command=start_scan)
scan_button.grid(row=2, column=0, columnspan=2, pady=10)

result_text = tk.Text(frame, wrap=tk.WORD, height=20)
result_text.grid(row=3, column=0, columnspan=2, pady=5)

root.mainloop()
