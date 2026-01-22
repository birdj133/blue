#!/bin/bash

# Ensure root
if [ "$EUID" -ne 0 ]; then echo "Run with sudo: sudo ./fw.sh"; exit 1; fi

# --- 1. CONFIG & STORAGE ---
DATA_DIR="/usr/local/share/.sys_data"
IP_FILE="$DATA_DIR/.accepted_ips"
PORT_FILE="$DATA_DIR/.accepted_ports"
mkdir -p "$DATA_DIR"
touch "$IP_FILE" "$PORT_FILE"

# --- 2. THE DASHBOARD ---
show_menu() {
    CHOICE=$(whiptail --title "ULTIMATE FIREWALL: FULL SUITE" --menu "Navigate with Arrows" 20 75 8 \
    "1" "Add Accepted IPs (Safe List)" \
    "2" "Add Allowed Ports" \
    "3" "APPLY ALL SECURITY RULES" \
    "4" "FUCK YOU (Panic: Absolute Kick)" \
    "5" "View Live Rules (-L)" \
    "6" "Exit" 3>&1 1>&2 2>&3)

    case $CHOICE in
        1) 
            IPS=$(whiptail --inputbox "Enter IPs (comma separated):" 10 60 3>&1 1>&2 2>&3)
            if [ ! -z "$IPS" ]; then echo "$IPS" | tr ',' '\n' | sed '/^$/d' >> "$IP_FILE"; fi
            show_menu 
            ;;
        2) 
            PORTS=$(whiptail --inputbox "Enter Ports (comma separated):" 10 60 3>&1 1>&2 2>&3)
            if [ ! -z "$PORTS" ]; then echo "$PORTS" | tr ',' '\n' | sed '/^$/d' >> "$PORT_FILE"; fi
            show_menu 
            ;;
        3) apply_rules "standard" ;;
        4) apply_rules "panic" ;;
        5) clear; iptables -L -n -v --line-numbers; echo -e "\nPress Enter..."; read; show_menu ;;
        *) exit ;;
    esac
}

# --- 3. THE ENGINE ---
apply_rules() {
    MODE=$1
    
    # --- PHASE A: THE KICK (Panic Mode Only) ---
    if [ "$MODE" == "panic" ]; then
        # Send the "FUCK YOU" message to their terminal
        echo "FUCK YOU! Connection Terminated." | wall 2>/dev/null
        
        # Flush kernel connection memory
        if command -v conntrack >/dev/null; then conntrack -F 2>/dev/null; fi
        
        # KILL unauthorized SSH sessions (The Physical Kick)
        MY_TTY=$(tty | sed 's|/dev/||')
        for pid in $(ps -ef | grep sshd | grep -v grep | awk '{print $2}'); do
            # Check if this PID is tied to your TTY; if not, kill it
            if ! ps -fp $pid | grep -q "$MY_TTY"; then
                kill -9 $pid 2>/dev/null
            fi
        done
    fi

    # --- PHASE B: CLEAN SLATE ---
    iptables -F
    iptables -X
    ip6tables -F 2>/dev/null

    # --- PHASE C: YOUR CUSTOM DROPS ---
    iptables -A INPUT -s 103.0.0.0/8 -j DROP
    iptables -A INPUT -s 43.0.0.0/8 -j DROP
    iptables -A INPUT -s 224.0.0.0/4 -j DROP # .mcast.net
    iptables -A INPUT -d 224.0.0.0/4 -j DROP
    iptables -A INPUT -s 240.0.0.0/5 -j DROP
    iptables -A INPUT -d 240.0.0.0/5 -j DROP
    iptables -A INPUT -s 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 255.255.255.255 -j DROP

    # Invalid Packet Filtering
    iptables -A INPUT -m state --state INVALID -j DROP
    iptables -A FORWARD -m state --state INVALID -j DROP
    iptables -A OUTPUT -m state --state INVALID -j DROP

    # --- PHASE D: WHITELIST ---
    iptables -A INPUT -i lo -j ACCEPT
    while read -r ip; do
        if [ ! -z "$ip" ]; then
            iptables -A INPUT -s "$ip" -j ACCEPT
            iptables -A INPUT -d "$ip" -j ACCEPT
        fi
    done < "$IP_FILE"

    # --- PHASE E: MODE-SPECIFIC LOGIC ---
    if [ "$MODE" == "panic" ]; then
        # REJECT with TCP Reset (Forces the other box to close the window)
        iptables -I INPUT 1 -p tcp -j REJECT --reject-with tcp-reset
        iptables -I INPUT 2 -j REJECT --reject-with icmp-admin-prohibited
    else
        # Allow Dynamic Ports
        while read -r port; do
            if [ ! -z "$port" ]; then
                iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
                iptables -A INPUT -p udp --dport "$port" -j ACCEPT
            fi
        done < "$PORT_FILE"

        # Honeyport 139
        iptables -A INPUT -p tcp --dport 139 -m recent --name portscan --set -j DROP
        iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP

        # SSH Guard (Rate Limit & Log)
        iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --set -j LOG --log-prefix "SSH ATTEMPT: "
        iptables -A INPUT -p tcp -m recent --name sshattempt --rcheck --seconds 86400 -j DROP
        
        # ICMP Rate Limit
        iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
        
        # Standard Established (Allows your current connection to stay)
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    fi

    # --- PHASE F: FINAL POLICIES ---
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    ip6tables -P INPUT DROP 2>/dev/null

    msg="Rules Applied Successfully."
    if [ "$MODE" == "panic" ]; then msg="FUCK YOU Mode Active. Intruders Sniped."; fi
    whiptail --msgbox "$msg" 10 50
    show_menu
}

# --- 4. START ---
show_menu
