#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then 
  echo "ERROR: Please run as root: sudo ./fw.sh"
  exit 1
fi

# --- 1. CONFIGURATION & HIDDEN STORAGE ---
DATA_DIR="/usr/local/share/.sys_data"
IP_FILE="$DATA_DIR/.accepted_ips"
PORT_FILE="$DATA_DIR/.accepted_ports"
mkdir -p "$DATA_DIR"
touch "$IP_FILE" "$PORT_FILE"

# --- 2. THE DASHBOARD ---
show_menu() {
    CHOICE=$(whiptail --title "Ultimate Security Firewall" --menu "Select an Option" 20 70 8 \
    "1" "Add Accepted IPs (Whitelisting)" \
    "2" "Add Allowed Ports" \
    "3" "APPLY ALL RULES LIVE" \
    "4" "View Current Rules (-L)" \
    "5" "FUCK YOU (Panic Button)" \
    "6" "Exit" 3>&1 1>&2 2>&3)

    case $CHOICE in
        1) 
            IPS=$(whiptail --inputbox "Enter IPs (comma separated):" 10 60 3>&1 1>&2 2>&3)
            echo "$IPS" | tr ',' '\n' | sed '/^$/d' >> "$IP_FILE"
            show_menu ;;
        2) 
            PORTS=$(whiptail --inputbox "Enter Ports (comma separated):" 10 60 3>&1 1>&2 2>&3)
            echo "$PORTS" | tr ',' '\n' | sed '/^$/d' >> "$PORT_FILE"
            show_menu ;;
        3) apply_rules "standard" ;;
        4) clear; iptables -L -n -v --line-numbers; echo -e "\nPress Enter..."; read; show_menu ;;
        5) apply_rules "panic" ;;
        *) exit ;;
    esac
}

# --- 3. THE ENGINE ---
apply_rules() {
    MODE=$1
    
    # KICK ACTIVE SESSIONS: Force kernel to drop everyone not yet whitelisted
    if command -v conntrack >/dev/null; then
        conntrack -F 2>/dev/null
    fi

    # Flush all current rules
    iptables -F
    iptables -X
    ip6tables -F 2>/dev/null

    # A. ATTACKER SUBNETS & BOGONS (The "Hard" Drops)
    iptables -A INPUT -s 103.0.0.0/8 -j DROP
    iptables -A INPUT -s 43.0.0.0/8 -j DROP
    iptables -A INPUT -s 224.0.0.0/4 -j DROP # .mcast.net
    iptables -A INPUT -s 240.0.0.0/5 -j DROP
    iptables -A INPUT -s 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 255.255.255.255 -j DROP

    # B. INVALID PACKET FILTERING
    iptables -A FORWARD -m state --state INVALID -j DROP
    iptables -A OUTPUT -m state --state INVALID -j DROP
    iptables -A INPUT -m state --state INVALID -j DROP

    # C. ALLOW LOOPBACK
    iptables -A INPUT -i lo -j ACCEPT

    # D. THE ALLOW LIST (Whitelisted IPs priority)
    while read ip; do
        [ ! -z "$ip" ] && iptables -A INPUT -s "$ip" -j ACCEPT
        [ ! -z "$ip" ] && iptables -A INPUT -d "$ip" -j ACCEPT
    done < "$IP_FILE"

    if [ "$MODE" == "panic" ]; then
        # E. THE PANIC KICK
        # Sends a TCP Reset and ICMP Prohibited message ("FUCK YOU" in network terms)
        iptables -A INPUT -j LOG --log-prefix "FUCK YOU - KICKED: "
        iptables -A INPUT -p tcp -j REJECT --reject-with tcp-reset
        iptables -A INPUT -j REJECT --reject-with icmp-admin-prohibited
    else
        # F. ALLOW PORTS (Standard Mode Only)
        while read port; do
            [ ! -z "$port" ] && iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            [ ! -z "$port" ] && iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        done < "$PORT_FILE"

        # G. HONEYPORT & PORT SCAN PROTECTION (Port 139)
        iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j DROP
        iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP

        # H. SSH ATTEMPT LOGGING & RATE LIMITING
        iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --set -j LOG --log-prefix "SSH ATTEMPT: "
        iptables -A INPUT -p tcp -m recent --name sshattempt --rcheck --seconds 86400 -j DROP
        
        # I. ICMP RATE LIMITING
        iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
    fi

    # J. FINAL POLICIES
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    ip6tables -P INPUT DROP 2>/dev/null

    MSG="Firewall Active."
    [ "$MODE" == "panic" ] && MSG="FUCK YOU! Connection killed and unknown users kicked."
    whiptail --msgbox "$MSG" 10 50
}

show_menu
