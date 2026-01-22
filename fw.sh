#!/bin/bash

# Ensure root
if [ "$EUID" -ne 0 ]; then echo "Please run with sudo: sudo ./fw.sh"; exit 1; fi

# --- CONFIG & STORAGE ---
DATA_DIR="/usr/local/share/.sys_data"
IP_FILE="$DATA_DIR/.accepted_ips"
PORT_FILE="$DATA_DIR/.accepted_ports"
mkdir -p "$DATA_DIR"
touch "$IP_FILE" "$PORT_FILE"

show_menu() {
    CHOICE=$(whiptail --title "ULTIMATE FIREWALL DASHBOARD" --menu "Arrow keys to move | Enter to select" 20 75 8 \
    "1" "Add Accepted IPs (Your Safe List)" \
    "2" "Add Allowed Ports (Web, DNS, etc.)" \
    "3" "APPLY ALL SECURITY RULES" \
    "4" "FUCK YOU (Panic: Kick & Lockdown)" \
    "5" "View Live Rules (-L)" \
    "6" "Exit" 3>&1 1>&2 2>&3)

    case $CHOICE in
        1) IPS=$(whiptail --inputbox "Enter IPs (comma separated):" 10 60 3>&1 1>&2 2>&3)
           echo "$IPS" | tr ',' '\n' | sed '/^$/d' >> "$IP_FILE"; show_menu ;;
        2) PORTS=$(whiptail --inputbox "Enter Ports (comma separated):" 10 60 3>&1 1>&2 2>&3)
           echo "$PORTS" | tr ',' '\n' | sed '/^$/d' >> "$PORT_FILE"; show_menu ;;
        3) apply_rules "standard" ;;
        4) apply_rules "panic" ;;
        5) clear; iptables -L -n -v --line-numbers; echo -e "\nPress Enter..."; read; show_menu ;;
        *) exit ;;
    esac
}

apply_rules() {
    MODE=$1
    
    # 1. THE "FUCK YOU" KICK LOGIC
    if [ "$MODE" == "panic" ]; then
        # Send the message to their terminal screen
        echo "FUCK YOU! Connection Terminated." | wall
        
        # Flush kernel connection memory
        if command -v conntrack >/dev/null; then conntrack -F 2>/dev/null; fi
        
        # KILL ALL SSH PROCESSES except your own session
        # This is the 'physical' kick out of the box
        MY_TTY=$(tty | cut -d'/' -f3,4)
        who -u | grep -v "$MY_TTY" | awk '{print $4}' | xargs kill -9 2>/dev/null
    fi

    # 2. FLUSH EVERYTHING
    iptables -F
    iptables -X
    ip6tables -F 2>/dev/null

    # 3. YOUR FULL RULES (The Bogons & Attacker Subnets)
    iptables -A INPUT -s 103.0.0.0/8 -j DROP
    iptables -A INPUT -s 43.0.0.0/8 -j DROP
    iptables -A INPUT -s 224.0.0.0/4 -j DROP # .mcast.net
    iptables -A INPUT -s 240.0.0.0/5 -j DROP
    iptables -A INPUT -s 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 255.255.255.255 -j DROP

    # 4. INVALID STATE PROTECTION
    iptables -A INPUT -m state --state INVALID -j DROP
    iptables -A FORWARD -m state --state INVALID -j DROP
    iptables -A OUTPUT -m state --state INVALID -j DROP

    # 5. ALLOW LOOPBACK
    iptables -A INPUT -i lo -j ACCEPT

    # 6. APPLY ALLOW LIST (Only these IPs survive)
    while read ip; do
        [ ! -z "$ip" ] && iptables -A INPUT -s "$ip" -j ACCEPT
        [ ! -z "$ip" ] && iptables -A INPUT -d "$ip" -j ACCEPT
    done < "$IP_FILE"

    if [ "$MODE" == "panic" ]; then
        # 7. PANIC REJECTS (At the TOP of the chain)
        iptables -I INPUT 1 -p tcp -j REJECT --reject-with tcp-reset
        iptables -I INPUT 2 -j REJECT --reject-with icmp-admin-prohibited
    else
        # 8. STANDARD RULES (Honeyport & SSH Guard)
        while read port; do
            [ ! -z "$port" ] && iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            [ ! -z "$port" ] && iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        done < "$PORT_FILE"

        # Honeyport 139 (Auto-ban for 24 hours)
        iptables -A INPUT -p tcp --dport 139 -m recent --name portscan --set -j DROP
        iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP

        # SSH Guard (Port 22 Rate Limiting & Logging)
        iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --set -j LOG --log-prefix "SSH ATTEMPT: "
        iptables -A INPUT -p tcp -m recent --name sshattempt --rcheck --seconds 86400 -j DROP
        
        # ICMP Rate Limit
        iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
        
        # Standard Established (Skip this in Panic Mode)
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    fi

    # 9. FINAL POLICIES
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    ip6tables -P INPUT DROP 2>/dev/null

    msg="Rules Applied."
    [ "$MODE" == "panic" ] && msg="FUCK YOU Mode Active. All intruders kicked."
    whiptail --msgbox "$msg" 10 50
}

show_menu
