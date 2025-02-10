import os
import subprocess
import requests
import time
import re
import socket
from threading import Thread

# Install required packages
subprocess.run(["pip", "install", "-r", "requirements.txt"], check=True)

# Discord webhook URL
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/your-webhook-id"

# ASCII banner
BANNER = """
 ▄████▄   ▒█████    ▄████  ███▄    █  ██▓    ██▀███  ▓█████ ▄▄▄       ██▓███  ▓█████  ██▀███  
▒██▀ ▀█  ▒██▒  ██▒ ██▒ ▀█▒ ██ ▀█   █ ▓██▒   ▓██ ▒ ██▒▓█   ▀▒████▄    ▓██░  ██▒▓█   ▀ ▓██ ▒ ██▒
▒▓█    ▄ ▒██░  ██▒▒██░▄▄▄░▓██  ▀█ ██▒▒██▒   ▓██ ░▄█ ▒▒███  ▒██  ▀█▄  ▓██░ ██▓▒▒███   ▓██ ░▄█ ▒
▒▓▓▄ ▄██▒▒██   ██░░▓█  ██▓▓██▒  ▐▌██▒░██░   ▒██▀▀█▄  ▒▓█  ▄░██▄▄▄▄██ ▒██▄█▓▒ ▒▒▓█  ▄ ▒██▀▀█▄  
▒ ▓███▀ ░░ ████▓▒░░▒▓███▀▒▒██░   ▓██░░██░   ░██▓ ▒██▒░▒████▒▓█   ▓██▒▒██▒ ░  ░░▒████▒░██▓ ▒██▒
░ ░▒ ▒  ░░ ▒░▒░▒░  ░▒   ▒ ░ ▒░   ▒ ▒ ░▓     ░ ▒▓ ░▒▓░░░ ▒░ ░▒▒   ▓▒█░▒▓▒░ ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░
  ░  ▒     ░ ▒ ▒░   ░   ░ ░ ░░   ░ ▒░ ▒ ░     ░▒ ░ ▒░ ░ ░  ░ ▒   ▒▒ ░░▒ ░      ░ ░  ░  ░▒ ░ ▒░
░        ░ ░ ░ ▒  ░ ░   ░    ░   ░ ░  ▒ ░     ░░   ░    ░    ░   ▒   ░░          ░     ░░   ░ 
░ ░          ░ ░        ░          ░  ░        ░        ░  ░     ░  ░            ░  ░   ░     
░                                                                                             
"""

# Center the banner in the terminal
def centered_banner():
    terminal_width = os.get_terminal_size().columns
    banner_lines = BANNER.splitlines()
    centered_lines = [line.center(terminal_width) for line in banner_lines]
    return "\n".join(centered_lines)

# Print the banner with a delay
def print_banner():
    print(centered_banner())
    time.sleep(1)

# Loading animation
def loading_animation():
    animation = ["|", "/", "-", "\\"]
    for i in range(30):
        print(f"\rPentesting... {animation[i % len(animation)]}", end="", flush=True)
        time.sleep(0.1)

# Run a system command
def run_command(command, description):
    try:
        print(f"\n[+] Running {description}...")
        result = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        return f"--- {description} Results ---\n{result}\n"
    except subprocess.CalledProcessError as e:
        return f"--- {description} Error ---\n{e.output}\n"

# Pentesting functions
def run_whois(target):
    return run_command(["whois", target], "Whois")

def run_nmap(target):
    return run_command(["nmap", "-A", target], "Nmap")

def run_gobuster(target):
    return run_command(["gobuster", "dir", "-u", target, "-w", "/usr/share/wordlists/dirb/common.txt"], "Gobuster")

def run_nikto(target):
    return run_command(["nikto", "-h", target], "Nikto")

def run_sublist3r(target):
    return run_command(["sublist3r", "-d", target], "Sublist3r")

def run_wpscan(target):
    return run_command(["wpscan", "--url", target, "--enumerate", "u"], "WPScan")

# FFUF integration
def run_ffuf(target):
    print("\n[+] Running FFUF (Fuzz Faster U Fool)...")
    try:
        # Use a common wordlist for directory fuzzing
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        ffuf_command = [
            "ffuf",
            "-u", f"{target}/FUZZ",
            "-w", wordlist,
            "-c"  # Clean output
        ]
        result = subprocess.check_output(ffuf_command, stderr=subprocess.STDOUT, text=True)
        return f"--- FFUF Results ---\n{result}\n"
    except subprocess.CalledProcessError as e:
        return f"--- FFUF Error ---\n{e.output}\n"

# Placeholder for tools requiring more setup
def placeholder_tool(name):
    print(f"\n[+] Running {name} (placeholder)...")
    time.sleep(2)
    return f"--- {name} Results ---\n(Placeholder) No vulnerabilities found.\n"

# Send results to Discord
def send_to_discord(report):
    print("\n[+] Sending report to Discord...")
    try:
        data = {"content": f"```\n{report}\n```"}
        response = requests.post(DISCORD_WEBHOOK_URL, json=data)
        if response.status_code == 204:
            print("[+] Report sent successfully!")
        else:
            print(f"[-] Failed to send report. HTTP Status: {response.status_code}")
    except Exception as e:
        print(f"[-] Error sending report to Discord: {e}")

# Validate target input
def validate_target(target):
    # Check if it's an IPv4 or IPv6 address
    try:
        socket.inet_pton(socket.AF_INET, target)  # Check for IPv4
        return "IPv4"
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, target)  # Check for IPv6
        return "IPv6"
    except socket.error:
        pass

    # Check if it's a valid domain or URL
    domain_regex = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,6}$"
    url_regex = r"^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([\/\w .-]*)*\/?$"

    if re.match(domain_regex, target):
        return "Domain"
    elif re.match(url_regex, target):
        return "URL"

    return None

# Main pentesting function
def pentest(target):
    print("[+] Starting pentesting...")
    results = []

    # Run selected tools
    results.append(run_whois(target))
    results.append(run_nmap(target))
    results.append(run_gobuster(target))
    results.append(run_nikto(target))
    results.append(run_sublist3r(target))
    results.append(run_wpscan(target))
    results.append(run_ffuf(target))  # FFUF integrated here

    # Add placeholders for additional tools
    results.append(placeholder_tool("SQLMap"))
    results.append(placeholder_tool("Hydra"))
    results.append(placeholder_tool("Metasploit"))
    results.append(placeholder_tool("Recon-ng"))
    results.append(placeholder_tool("theHarvester"))
    results.append(placeholder_tool("Shodan"))
    results.append(placeholder_tool("Amass"))
    results.append(placeholder_tool("WhatWeb"))
    results.append(placeholder_tool("XSStrike"))
    results.append(placeholder_tool("Arachni"))
    results.append(placeholder_tool("WFuzz"))
    results.append(placeholder_tool("Burp Suite"))
    results.append(placeholder_tool("OWASP ZAP"))
    results.append(placeholder_tool("FFUF"))

    # Combine all results
    full_report = "\n".join(results)
    print("\n[+] Pentest complete!")

    # Send the report to Discord
    send_to_discord(full_report)

# Main script logic
if __name__ == "__main__":
    print_banner()
    target = input("\nEnter the target (URL, IP, or domain): ").strip()

    # Validate target
    target_type = validate_target(target)
    if not target_type:
        print("[-] Invalid target. Please enter a valid IP address, domain, or URL.")
        exit(1)
    else:
        print(f"[+] Target identified as: {target_type}")

    # Start the loading animation in a separate thread
    loading_thread = Thread(target=loading_animation)
    loading_thread.start()

    # Perform pentesting
    pentest(target)

    # Ensure the loading animation stops
    loading_thread.join()
    print("\nDone!")
