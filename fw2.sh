#!/bin/bash

# Ensure root
if [ "$EUID" -ne 0 ]; then echo "Run with sudo: sudo ./fw.sh"; exit 1; fi

# --- 1. CONFIG & STORAGE ---
DATA_DIR="/usr/local/share/.sys_data"
IP_FILE="$DATA_DIR/.accepted_ips"
PORT_FILE="$DATA_DIR/.accepted_ports"
RULES_V4="/etc/iptables/rules.v4"
RULES_V6="/etc/iptables/rules.v6"

mkdir -p "$DATA_DIR"
mkdir -p /etc/iptables
touch "$IP_FILE" "$PORT_FILE"

# --- 2. THE DASHBOARD ---
show_menu() {
    CHOICE=$(whiptail --title "ULTIMATE FIREWALL: FULL SUITE" --menu "Navigate with Arrows" 20 75 8 \
    "1" "View Live / Saved Rules" \
    "2" "Add Accepted IPs (Safe List)" \
    "3" "Add Allowed Ports" \
    "4" "APPLY ALL SECURITY RULES" \
    "5" "FIRST TIME? (Panic: Absolute Kick)" \
    "6" "Clear All Lists (Reset IPs/Ports)" \
    "7" "Exit" 3>&1 1>&2 2>&3)

    case $CHOICE in
        1) 
            clear
            echo "--- CURRENT KERNEL RULES ---"
            iptables -L -n -v --line-numbers
            echo -e "\n--- PERSISTENT SAVE FILE ($RULES_V4) ---"
            [ -f "$RULES_V4" ] && cat "$RULES_V4" || echo "No save file yet."
            echo -e "\nPress Enter to return..."
            read; show_menu ;;
        2) 
            IPS=$(whiptail --inputbox "Enter IPs (comma separated):" 10 60 3>&1 1>&2 2>&3)
            if [ ! -z "$IPS" ]; then echo "$IPS" | tr ',' '\n' | sed '/^$/d' >> "$IP_FILE"; fi
            show_menu ;;
        3) 
            PORTS=$(whiptail --inputbox "Enter Ports (comma separated):" 10 60 3>&1 1>&2 2>&3)
            if [ ! -z "$PORTS" ]; then echo "$PORTS" | tr ',' '\n' | sed '/^$/d' >> "$PORT_FILE"; fi
            show_menu ;;
        4) apply_rules "standard" ;;
        5) apply_rules "panic" ;;
        6) 
            > "$IP_FILE"; > "$PORT_FILE"
            whiptail --msgbox "IP and Port lists have been cleared." 10 50
            show_menu ;;
        *) exit ;;
    esac
}

# --- 3. THE ENGINE ---
apply_rules() {
    MODE=$1
    
    # --- PHASE A: CLEAN SLATE ---
    iptables -F
    iptables -X
    iptables -t nat -F 2>/dev/null
    iptables -t mangle -F 2>/dev/null
    ip6tables -F 2>/dev/null
    ip6tables -X 2>/dev/null

    # --- PHASE B: WHITELIST ---
    iptables -A INPUT -i lo -j ACCEPT
    while read -r ip; do
        if [ ! -z "$ip" ]; then
            iptables -A INPUT -s "$ip" -j ACCEPT
            iptables -A INPUT -d "$ip" -j ACCEPT
        fi
    done < "$IP_FILE"

    # --- PHASE C: SPECIFIC DROPS ---
    iptables -A INPUT -s 224.0.0.0/4 -j DROP
    iptables -A INPUT -d 224.0.0.0/4 -j DROP
    iptables -A INPUT -s 240.0.0.0/5 -j DROP
    iptables -A INPUT -d 240.0.0.0/5 -j DROP
    iptables -A INPUT -s 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 0.0.0.0/8 -j DROP
    iptables -A INPUT -s 239.255.255.0/24 -j DROP
    iptables -A INPUT -d 239.255.255.0/24 -j DROP
    iptables -A INPUT -s 255.255.255.255 -j DROP
    iptables -A INPUT -d 255.255.255.255 -j DROP

    # --- PHASE D: LOGGING & ATTACK PREVENTION ---
    iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-prefix "ICMP Attempt: " --log-level 4
    
    iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:" --log-level 4
    iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j DROP
    iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
    iptables -A INPUT -m recent --name portscan --remove

    iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

    iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --set -j LOG --log-prefix "SSH ATTEMPT: " --log-level 4
    iptables -A INPUT -m recent --name sshattempt --rcheck --seconds 86400 -j DROP

    # --- PHASE E: DYNAMIC PORTS & ESTABLISHED ---
    if [ "$MODE" != "panic" ]; then
        while read -r port; do
            if [ ! -z "$port" ]; then
                iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
                iptables -A INPUT -p udp --dport "$port" -j ACCEPT
            fi
        done < "$PORT_FILE"
        
        # Standard established traffic
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    fi

    # --- PHASE F: INVALID PACKET LOGGING ---
    iptables -A FORWARD -m state --state INVALID -j LOG --log-prefix "Forward Invalid Drop: " --log-level 4
    iptables -A FORWARD -m state --state INVALID -j DROP
    iptables -A OUTPUT -m state --state INVALID -j LOG --log-prefix "OUTPUT Invalid Drop: " --log-level 4
    iptables -A OUTPUT -m state --state INVALID -j DROP
    
    iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
    iptables -A FORWARD -m recent --name portscan --remove

    # --- PHASE G: FINAL POLICIES & PANIC ---
    if [ "$MODE" == "panic" ]; then
        echo "FIRST TIME? Connection Terminated." | wall 2>/dev/null
        iptables -I INPUT 1 -p tcp -j REJECT --reject-with tcp-reset
        
        MY_TTY=$(tty | sed 's|/dev/||')
        for pid in $(ps -ef | grep sshd | grep -v grep | awk '{print $2}'); do
            if ! ps -fp $pid | grep -q "$MY_TTY"; then kill -9 $pid 2>/dev/null; fi
        done
    fi

    iptables -A INPUT -j REJECT
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    ip6tables -A INPUT -j DROP
    ip6tables -P INPUT DROP

    # --- PHASE H: PERSISTENCE ---
    iptables-save > "$RULES_V4"
    ip6tables-save > "$RULES_V6"

    msg="Rules Applied Successfully."
    if [ "$MODE" == "panic" ]; then msg="FIRST TIME? Mode Active. Unauthorized sessions purged."; fi
    whiptail --msgbox "$msg" 10 50
    show_menu
}

# --- 4. START ---
show_menu
