#!/bin/bash

echo "[+] Updating system..."
sudo apt update -y

echo "[+] Installing required tools..."
sudo apt install -y ffuf gobuster whois nmap nikto sublist3r wpscan dirb

echo "[+] Installation complete!"
