import os
import subprocess
import requests
import time
import re
import socket
from threading import Thread, Event

# Discord webhook URL (substitua pelo seu webhook real)
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/your-webhook-id"

# Banner
BANNER = """
 ▄████▄   ▒█████    ▄████  ███▄    █  ██▓
▒██▀ ▀█  ▒██▒  ██▒ ██▒ ▀█▒ ██ ▀█   █ ▓██▒
▒▓█    ▄ ▒██░  ██▒▒██░▄▄▄░▓██  ▀█ ██▒▒██▒
▒▓▓▄ ▄██▒▒██   ██░░▓█  ██▓▓██▒  ▐▌██▒░██░
▒ ▓███▀ ░░ ████▓▒░░▒▓███▀▒▒██░   ▓██░░██░
░ ░▒ ▒  ░░ ▒░▒░▒░  ░▒   ▒ ░ ▒░   ▒ ▒ ░▓  
  ░  ▒     ░ ▒ ▒░   ░   ░ ░ ░░   ░ ▒░ ▒ ░
░        ░ ░ ░ ▒  ░ ░   ░    ░   ░ ░  ▒ ░
░ ░          ░ ░        ░          ░  ░  
░                                        
"""

# Print banner
def print_banner():
    os.system("clear" if os.name == "posix" else "cls")
    print(BANNER)
    time.sleep(1)

# Loading animation
loading_stop = Event()

def loading_animation():
    animation = ["|", "/", "-", "\\"]
    while not loading_stop.is_set():
        for frame in animation:
            print(f"\rPentesting... {frame}", end="", flush=True)
            time.sleep(0.1)

# Run command with subprocess
def run_command(command, description):
    try:
        print(f"\n[+] Running {description}...")
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return f"--- {description} Results ---\n{result.stdout}\n"
    except subprocess.CalledProcessError as e:
        return f"--- {description} Error ---\n{e.stderr}\n"

# Pentesting tools
def run_whois(target): return run_command(["whois", target], "Whois")
def run_nmap(target): return run_command(["nmap", "-A", target], "Nmap")
def run_gobuster(target): return run_command(["gobuster", "dir", "-u", target, "-w", "/usr/share/wordlists/dirb/common.txt"], "Gobuster")
def run_nikto(target): return run_command(["nikto", "-h", target], "Nikto")
def run_ffuf(target): return run_command(["ffuf", "-u", f"{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-c"], "FFUF")
def run_sqlmap(target): return run_command(["sqlmap", "-u", target, "--batch", "--level=5", "--risk=3"], "SQLMap")
def run_hydra(target): return run_command(["hydra", "-L", "users.txt", "-P", "passwords.txt", target, "ssh"], "Hydra (Brute Force)")
def run_whatweb(target): return run_command(["whatweb", target], "WhatWeb")
def run_xsstrike(target): return run_command(["xsstrike", "-u", target], "XSStrike (XSS Scanner)")

# Validate target
def validate_target(target):
    try:
        socket.inet_pton(socket.AF_INET, target)
        return "IPv4"
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, target)
        return "IPv6"
    except socket.error:
        pass

    domain_regex = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,6}$"
    url_regex = r"^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([\/\w .-]*)*\/?$"
    
    if re.match(domain_regex, target):
        return "Domain"
    elif re.match(url_regex, target):
        return "URL"
    return None

# Send results to Discord asynchronously
def send_to_discord(report):
    def _send():
        try:
            print("\n[+] Sending report to Discord...")
            data = {"content": f"```\n{report}\n```"}
            response = requests.post(DISCORD_WEBHOOK_URL, json=data)
            print("[+] Report sent!" if response.status_code == 204 else f"[-] Failed to send report. HTTP {response.status_code}")
        except Exception as e:
            print(f"[-] Error sending report: {e}")

    Thread(target=_send).start()

# Run pentest in parallel
def pentest(target):
    print("[+] Starting pentesting...")

    tools = [
        run_whois, run_nmap, run_gobuster, run_nikto, 
        run_ffuf, run_sqlmap, run_hydra, run_whatweb, run_xsstrike
    ]
    threads = []
    results = []

    def run_tool(tool):
        result = tool(target)
        results.append(result)

    for tool in tools:
        thread = Thread(target=run_tool, args=(tool,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    full_report = "\n".join(results)
    print("\n[+] Pentest complete!")
    send_to_discord(full_report)

# Main
if __name__ == "__main__":
    print_banner()
    target = input("\nEnter the target (URL, IP, or domain): ").strip()

    target_type = validate_target(target)
    if not target_type:
        print("[-] Invalid target. Please enter a valid IP address, domain, or URL.")
        exit(1)

    print(f"[+] Target identified as: {target_type}")

    loading_thread = Thread(target=loading_animation)
    loading_thread.start()

    pentest(target)

    loading_stop.set()
    loading_thread.join()
    print("\nDone!")
