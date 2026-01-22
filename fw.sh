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
BACKUP_DIR="/var/lib/.security_backup"

mkdir -p "$DATA_DIR" "$BACKUP_DIR"
touch "$IP_FILE" "$PORT_FILE"

# --- 2. BACKUP/RESTORE ---
save_backup() { cp "$IP_FILE" "$BACKUP_DIR/.ip_b"; cp "$PORT_FILE" "$BACKUP_DIR/.port_b"; }
restore_backup() { cp "$BACKUP_DIR/.ip_b" "$IP_FILE"; cp "$BACKUP_DIR/.port_b" "$PORT_FILE"; }

# --- 3. THE DASHBOARD ---
show_menu() {
    CHOICE=$(whiptail --title "Security Firewall Dashboard" --menu "Manage Rules" 20 70 8 \
    "1" "Add Accepted IPs (Jumpbox/Admin)" \
    "2" "Add Allowed Ports (Service Ports)" \
    "3" "Restore Golden Backup" \
    "4" "APPLY ALL RULES LIVE" \
    "5" "View Current Rules (-L)" \
    "6" "PANIC: Full Lockdown" \
    "7" "Exit" 3>&1 1>&2 2>&3)

    case $CHOICE in
        1) 
            IPS=$(whiptail --inputbox "Enter IPs/Subnets (comma separated):" 10 60 3>&1 1>&2 2>&3)
            echo "$IPS" | tr ',' '\n' | sed '/^$/d' >> "$IP_FILE"
            save_backup && show_menu ;;
        2) 
            PORTS=$(whiptail --inputbox "Enter Ports (e.g. 80, 443, 53):" 10 60 3>&1 1>&2 2>&3)
            echo "$PORTS" | tr ',' '\n' | sed '/^$/d' >> "$PORT_FILE"
            save_backup && show_menu ;;
        3) restore_backup; whiptail --msgbox "Restored from hidden backup." 10 40; show_menu ;;
        4) apply_rules "standard" ;;
        5) clear; iptables -L -n -v --line-numbers; echo -e "\nPress Enter..."; read; show_menu ;;
        6) apply_rules "panic" ;;
        *) exit ;;
    esac
}

# --- 4. THE FULL RULESET ---
apply_rules() {
    MODE=$1
    iptables -F
    iptables -X
    ip6tables -F 2>/dev/null

    # A. MANDATORY ATTACKER SUBETS (Requirement: Always Remain)
    iptables -A INPUT -s 103.0.0.0/8 -j DROP
    iptables -A INPUT -s 43.0.0.0/8 -j DROP
    
    # B. BOGON / MULTICAST FILTERING
    iptables -A INPUT -s 224.0.0.0/4 -j DROP
    iptables -A INPUT -d 224.0.0.0/4 -j DROP
    iptables -A INPUT -s 240.0.0.0/5 -j DROP
    iptables -A INPUT -d 240.0.0.0/5 -j DROP
    iptables -A INPUT -s 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 239.255.255.0/24 -j DROP
    iptables -A INPUT -d 255.255.255.255 -j DROP

    # C. INVALID STATE FILTERING (Log & Drop)
    iptables -A FORWARD -m state --state INVALID -j LOG --log-prefix "Forward Invalid Drop: " --log-level 4
    iptables -A FORWARD -m state --state INVALID -j DROP
    iptables -A OUTPUT -m state --state INVALID -j LOG --log-prefix "OUTPUT Invalid Drop: " --log-level 4
    iptables -A OUTPUT -m state --state INVALID -j DROP

    # D. ALLOW LOOPBACK
    iptables -A INPUT -i lo -j ACCEPT

    # E. APPLY USER WHITELIST (From Option 1)
    while read ip; do
        [ ! -z "$ip" ] && iptables -A INPUT -s "$ip" -j ACCEPT
        [ ! -z "$ip" ] && iptables -A INPUT -d "$ip" -j ACCEPT
    done < "$IP_FILE"

    if [ "$MODE" == "panic" ]; then
        iptables -A INPUT -j LOG --log-prefix "PANIC MODE: "
    else
        # F. ALLOW PORTS (From Option 2)
        while read port; do
            [ ! -z "$port" ] && iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            [ ! -z "$port" ] && iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        done < "$PORT_FILE"

        # G. HONEYPORT & PORT SCAN PROTECTION (Port 139)
        iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:" --log-level 4
        iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j DROP
        iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
        iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

        # H. SSH ATTEMPT LOGGING & RATE LIMITING
        iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --set -j LOG --log-prefix "SSH ATTEMPT: " --log-level 4
        iptables -A INPUT -p tcp -m recent --name sshattempt --rcheck --seconds 86400 -j DROP
        
        # I. ICMP LOGGING & RATE LIMITING
        iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-prefix "ICMP Attempt: " --log-level 4
        iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
    fi

    # J. FINAL POLICIES
    iptables -P OUTPUT ACCEPT
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -A INPUT -j REJECT
    iptables -A FORWARD -j REJECT
    ip6tables -P INPUT DROP # Nuke IPv6
    
    # Save to disk
    iptables-save > /etc/iptables.rules
    whiptail --msgbox "All Rules Active. System Protected." 10 50
}

show_menu
