import subprocess
import time

# ---------------- FIREWALL CORE FUNCTIONS ---------------- #

def run_cmd(cmd):
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def block_ip(ip):
    run_cmd(f'netsh advfirewall firewall add rule name="Block IP {ip}" dir=in action=block remoteip={ip}')
    print(f"[BLOCKED IP] {ip}")

def unblock_ip(ip):
    run_cmd(f'netsh advfirewall firewall delete rule name="Block IP {ip}"')
    print(f"[UNBLOCKED IP] {ip}")

def block_port(port):
    run_cmd(f'netsh advfirewall firewall add rule name="Block Port {port}" dir=in action=block protocol=TCP localport={port}')
    print(f"[BLOCKED PORT] {port}")

def allow_ip(ip, port):
    run_cmd(f'netsh advfirewall firewall add rule name="Allow {ip}:{port}" dir=in action=allow protocol=TCP localport={port} remoteip={ip}')
    print(f"[ALLOWED IP] {ip} on port {port}")

def block_ping():
    run_cmd('netsh advfirewall firewall add rule name="Block ICMP" protocol=icmpv4 dir=in action=block')
    print("[PING BLOCKED] ICMP disabled")

def block_outbound():
    run_cmd('netsh advfirewall firewall add rule name="Block Outbound" dir=out action=block')
    print("[OUTBOUND BLOCKED] All outbound traffic blocked")

def unblock_outbound():
    run_cmd('netsh advfirewall firewall delete rule name="Block Outbound"')
    print("[OUTBOUND UNBLOCKED]")

def block_application(app_path):
    run_cmd(f'netsh advfirewall firewall add rule name="Block App {app_path}" dir=out action=block program="{app_path}"')
    print(f"[APP BLOCKED] {app_path}")

def temporary_block(ip, seconds):
    block_ip(ip)
    print(f"[TEMP BLOCK] {ip} for {seconds} seconds")
    time.sleep(seconds)
    unblock_ip(ip)

# ---------------- SMART FIREWALL LOGIC ---------------- #

suspicious_ips = [
    "192.168.1.10",
    "192.168.1.20",
    "10.0.0.99"
]

blocked_ports = [21, 23, 445]  # FTP, Telnet, SMB

# ---------------- FIREWALL EXECUTION ---------------- #

print("\n🔥 PYTHON FIREWALL STARTED 🔥\n")

# 1. Block suspicious IPs
for ip in suspicious_ips:
    block_ip(ip)

# 2. Block dangerous ports
for port in blocked_ports:
    block_port(port)

# 3. Allow SSH only from trusted IP
allow_ip("192.168.1.5", 22)

# 4. Block Ping
block_ping()

# 5. Block outbound traffic (comment if not needed)
# block_outbound()

# 6. Block an application (example: Chrome)
# block_application(r"C:\Program Files\Google\Chrome\Application\chrome.exe")

# 7. Temporary block example
# temporary_block("192.168.1.30", 30)

print("\n✅ FIREWALL RULES APPLIED SUCCESSFULLY\n")
