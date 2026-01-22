#!/bin/bash

# --- 1. CONFIGURATION & HIDDEN STORAGE ---
DATA_DIR="/usr/local/share/.sys_data"
IP_FILE="$DATA_DIR/.accepted_ips"
PORT_FILE="$DATA_DIR/.accepted_ports"
BACKUP_DIR="/var/lib/.security_backup"
SCRIPT_PATH="/usr/local/bin/fw.sh"

# Ensure directories exist and are hidden from standard users
mkdir -p "$DATA_DIR" "$BACKUP_DIR"
touch "$IP_FILE" "$PORT_FILE"

# --- 2. AUTOMATIC ALIAS & SYSTEM INSTALL ---
# This ensures 'firewall', 'i', 'o', and 'f' work as commands
install_logic() {
    if [ "$0" != "$SCRIPT_PATH" ]; then
        cp "$0" "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
    fi

    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -f "$rc" ]; then
            grep -q "alias firewall=" "$rc" || echo "alias firewall='sudo $SCRIPT_PATH'" >> "$rc"
            grep -q "alias i=" "$rc" || echo "alias i='sudo iptables -A INPUT'" >> "$rc"
            grep -q "alias o=" "$rc" || echo "alias o='sudo iptables -A OUTPUT'" >> "$rc"
            grep -q "alias f=" "$rc" || echo "alias f='sudo iptables -A FORWARD'" >> "$rc"
        fi
    done
}
install_logic

# --- 3. DATA PERSISTENCE ---
save_backup() { cp "$IP_FILE" "$BACKUP_DIR/.ip_b"; cp "$PORT_FILE" "$BACKUP_DIR/.port_b"; }
restore_backup() { cp "$BACKUP_DIR/.ip_b" "$IP_FILE"; cp "$BACKUP_DIR/.port_b" "$PORT_FILE"; }

# --- 4. THE DASHBOARD (PROMPTS) ---
show_menu() {
    CHOICE=$(whiptail --title "Linux Firewall Dashboard" --menu "Use Arrows to Navigate" 20 70 8 \
    "1" "Add Accepted IPs (Jumpbox/Admin)" \
    "2" "Add Allowed Ports (Web/DNS/SSH)" \
    "3" "Restore Golden Backup" \
    "4" "APPLY FIREWALL RULES NOW" \
    "5" "View Current Table (-L)" \
    "6" "Panic Button: LOCKDOWN" \
    "7" "Exit" 3>&1 1>&2 2>&3)

    case $CHOICE in
        1) 
            IPS=$(whiptail --inputbox "Enter IP or Subnet (e.g., 192.168.40.0/24):" 10 60 3>&1 1>&2 2>&3)
            [ ! -z "$IPS" ] && echo "$IPS" >> "$IP_FILE" && save_backup
            show_menu ;;
        2) 
            PORTS=$(whiptail --inputbox "Enter Port Numbers (e.g., 80, 443, 53):" 10 60 3>&1 1>&2 2>&3)
            [ ! -z "$PORTS" ] && echo "$PORTS" | tr ',' '\n' >> "$PORT_FILE" && save_backup
            show_menu ;;
        3) restore_backup; whiptail --msgbox "Backup Restored." 8 30; show_menu ;;
        4) apply_rules "standard" ;;
        5) clear; iptables -L -n -v --line-numbers; echo -e "\nPress Enter to return..."; read; show_menu ;;
        6) 
            if whiptail --yesno "PANIC MODE: Drop ALL connections except whitelisted IPs?" 10 60; then
                apply_rules "panic"
            else
                show_menu
            fi ;;
        *) exit ;;
    esac
}

# --- 5. THE IPTABLES ENGINE ---
apply_rules() {
    MODE=$1
    # Flush existing rules to start fresh
    iptables -F
    iptables -X
    ip6tables -F
    ip6tables -X

    # MANDATORY: Block common attacker subnets & Bogons (Always remain)
    iptables -A INPUT -s 103.0.0.0/8 -j DROP
    iptables -A INPUT -s 43.0.0.0/8 -j DROP
    iptables -A INPUT -s 224.0.0.0/4 -j DROP
    iptables -A INPUT -d 224.0.0.0/4 -j DROP
    iptables -A INPUT -s 240.0.0.0/5 -j DROP
    iptables -A INPUT -d 240.0.0.0/5 -j DROP
    iptables -A INPUT -s 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 0.0.0.0/8 -j DROP
    iptables -A INPUT -d 239.255.255.0/24 -j DROP
    iptables -A INPUT -d 255.255.255.255 -j DROP

    # ALLOW LOOPBACK
    iptables -A INPUT -i lo -j ACCEPT

    # ALLOW DYNAMIC IPs (The Whitelist)
    while read ip; do
        [ -z "$ip" ] && continue
        iptables -A INPUT -s "$ip" -j ACCEPT
        iptables -A INPUT -d "$ip" -j ACCEPT
    done < "$IP_FILE"

    if [ "$MODE" == "panic" ]; then
        iptables -A INPUT -j LOG --log-prefix "PANIC MODE ACTIVATED: "
    else
        # ALLOW DYNAMIC PORTS (Standard Mode Only)
        while read port; do
            [ -z "$port" ] && continue
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        done < "$PORT_FILE"

        # HONEYPORT & PORT SCAN PROTECTION
        iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:" --log-level 4
        iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j DROP
        iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP

        # SSH GUARD
        iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --set -j LOG --log-prefix "SSH ATTEMPT: " --log-level 4
        iptables -A INPUT -p tcp -m recent --name sshattempt --rcheck --seconds 86400 -j DROP
    fi

    # GLOBAL DROPS & POLICIES
    iptables -A FORWARD -m state --state INVALID -j DROP
    iptables -A OUTPUT -m state --state INVALID -j DROP
    
    iptables -P OUTPUT ACCEPT
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    ip6tables -P INPUT DROP # Nuke IPv6
    
    # Save rules
    iptables-save > /etc/iptables.rules
    
    MSG="Rules Applied Successfully."
    [ "$MODE" == "panic" ] && MSG="!!! SYSTEM IN LOCKDOWN !!! Only Whitelisted IPs allowed."
    whiptail --msgbox "$MSG" 10 50
}

# --- 6. LAUNCH ---
show_menu
