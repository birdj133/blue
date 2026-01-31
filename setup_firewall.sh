#!/bin/bash
# ---------------------------------------------------------
# UNIFIED FIREWALL DASHBOARD - LAB SIMULATION VERSION
# Includes: Screenshot Rules + SSH Redirect Honeypot
# ---------------------------------------------------------

# EDIT THIS LINE IN YOUR LAB:
TARGET_MESSAGE="GET FUCKED NERD!!! INTRUDER HAS BEEN NEUTRALIZED!!!"

if [ "$EUID" -ne 0 ]; then
  whiptail --title "Permission Error" --msgbox "Please run as root (use sudo)." 10 45
  exit 1
fi

# Variables
WHITELIST=""
SSH_ALLOW=""
PORTS=""

apply_rules() {
  # --- 1. Flush & Reset ---
  iptables -F
  iptables -X
  iptables -t nat -F
  iptables -t mangle -F

  # --- 2. Default Policies ---
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT

  # --- 3. Whitelist (Highest Priority) ---
  for ip in ${WHITELIST//,/ }; do
    [[ -n "$ip" ]] && iptables -A INPUT -s "$ip" -j ACCEPT
  done

  # --- 4. Rules from your Screenshot ---
  # ICMP Scoring Engine
  iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT

  # Bogon / Reserved / Multicast Drops
  iptables -A INPUT -s 0.0.0.0/8 -j DROP
  iptables -A INPUT -d 0.0.0.0/8 -j DROP
  iptables -A INPUT -s 224.0.0.0/4 -j DROP
  iptables -A INPUT -s 224.0.0.9/8 -j DROP
  iptables -A INPUT -s 239.255.255.0/24 -j DROP
  iptables -A INPUT -s 255.255.255.255/5 -j DROP
  iptables -A INPUT -s 255.255.255.255/32 -j DROP

  # Portscan Protection
  iptables -A INPUT -p tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:" --log-level 4
  iptables -A INPUT -p tcp --dport 139 -m recent --name portscan --set -j DROP
  iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT

  # --- 5. SSH Logic (The Redirect) ---
  # Allow Whitelisted SSH Users
  for ip in ${SSH_ALLOW//,/ }; do
    [[ -n "$ip" ]] && iptables -A INPUT -p tcp -s "$ip" --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  done

  # REDIRECT everyone else to the honeypot listener on 2222
  iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

  # --- 6. General Traffic & Ports ---
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  for port in ${PORTS//,/ }; do
    [[ -n "$port" ]] && iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
  done

  # --- 7. Final Cleanup ---
  iptables -A INPUT -m state --state INVALID -j DROP
  iptables -A INPUT -j DROP

  # Start the background listener for the message
  pkill -f "nc -l -p 2222" # Kill old one if it exists
  nohup sh -c "while true; do echo '$TARGET_MESSAGE' | nc -l -p 2222 -q 1; done" >/dev/null 2>&1 &

  whiptail --title "Firewall Armed" --msgbox "Rules applied! Unauthorized SSH is now being redirected to your message." 10 65
}

# --- Menu Loop ---
while true; do
  CHOICE=$(whiptail --title "Interactive Lab Firewall" --menu "Navigate with arrows:" 20 70 10 \
    "1" "Set Whitelist IPs" \
    "2" "Set SSH Allowed IPs" \
    "3" "Set Allowed Ports" \
    "4" "Apply All Rules (Includes Redirect)" \
    "5" "Reset Firewall (Accept All)" \
    "6" "Exit" 3>&2 2>&1 1>&3)

  case "$CHOICE" in
    1) WHITELIST=$(whiptail --inputbox "Whitelist IPs (comma-separated):" 10 60 "$WHITELIST" 3>&1 1>&2 2>&3) ;;
    2) SSH_ALLOW=$(whiptail --inputbox "Allowed SSH IPs:" 10 60 "$SSH_ALLOW" 3>&1 1>&2 2>&3) ;;
    3) PORTS=$(whiptail --inputbox "Open Ports:" 10 60 "$PORTS" 3>&1 1>&2 2>&3) ;;
    4) apply_rules ;;
    5) 
       iptables -F && iptables -t nat -F && iptables -P INPUT ACCEPT
       pkill -f "nc -l -p 2222"
       whiptail --msgbox "Firewall Reset." 10 40
       ;;
    6) break ;;
  esac
done
