#!/bin/bash

# --- CONFIGURATION ---
STEALTH_PATH="/usr/lib/.systemd-cache-auth"

# Variables
WHITELIST_IPS=""
declare -a TCP_PORTS
declare -a UDP_PORTS

# Check for sudo
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: Please run with sudo"
   exit 1
fi

show_menu() {
    echo -e "\n\e[1;33m======================================\e[0m"
    echo -e "\e[1;31m   COMPETITION DEFENSE DASHBOARD      \e[0m"
    echo -e "\e[1;33m======================================\e[0m"
    echo "1) LIST Rules (Screenshot Mode)"
    echo "2) ENTER Whitelist IPs"
    echo "3) ENTER Service Ports (TCP or UDP)"
    echo "4) APPLY Spreadsheet Rules"
    echo "5) PURGE RED TEAM (Kick & Message)"
    echo "6) RECALL (Persistence Recovery)"
    echo "7) EXIT"
    echo -n "Select: "
}

set_ips() {
    echo -e "\n--- [ IP WHITELIST ] ---"
    echo "Enter all trusted IPs separated by spaces:"
    read -p "> " WHITELIST_IPS
    echo "[+] IPs stored."
}

set_ports() {
    echo -e "\n--- [ PORT CONFIGURATION ] ---"
    echo "Enter ports one by one. Type 'done' to finish."
    TCP_PORTS=()
    UDP_PORTS=()
    while true; do
        read -p "Port number (or 'done'): " PN
        [[ "$PN" == "done" ]] && break
        read -p "Protocol for $PN (tcp/udp): " PT
        if [[ "$PT" == "tcp" ]]; then
            TCP_PORTS+=("$PN")
        else
            UDP_PORTS+=("$PN")
        fi
    done
}

apply_rules() {
    if [[ -z "$WHITELIST_IPS" ]]; then
        echo "[!] WARNING: Whitelist is empty. Proceeding anyway..."
    fi

    echo "[!] Wiping tables and applying spreadsheet rules..."
    
    # Reset
    iptables -P INPUT ACCEPT
    iptables -F
    iptables -X
    iptables -Z

    # 1. Whitelists (i and o)
    for ip in $WHITELIST_IPS; do
        iptables -A INPUT -s $ip -j ACCEPT
        iptables -A OUTPUT -d $ip -j ACCEPT
    done

    # 2. Bogon Drops (i)
    for b in "224.0.0.0/4" "240.0.0.0/5" "0.0.0.0/8" "239.255.255.0/24" "255.255.255.255"; do
        iptables -A INPUT -s $b -j DROP
        iptables -A INPUT -d $b -j DROP
    done

    # 3. ICMP Logging & Scoring (From your list)
    iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-prefix "ICMP Attempt: " --log-level 4
    # Allowing ICMP from entire whitelist for scoring flexibility
    for ip in $WHITELIST_IPS; do
        iptables -A INPUT -s $ip -p icmp --icmp-type 8 -j ACCEPT
    done

    # 4. Honeypot (f)
    iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:" --log-level 4
    iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j DROP

    # 5. Flood Prot
    iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
    iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
    iptables -A INPUT -m recent --name portscan --remove

    # 6. SSH Specific Access (Using your comma-separated requirement)
    iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --set -j LOG --log-prefix "SSH ATTEMPT: " --log-level 4
    
    SSH_COMMA_LIST=$(echo $WHITELIST_IPS | sed 's/ /,/g')
    if [[ ! -z "$SSH_COMMA_LIST" ]]; then
        iptables -A INPUT -p tcp --dport 22 -s $SSH_COMMA_LIST -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    fi
    iptables -A INPUT -p tcp -m recent --name sshattempt --rcheck --seconds 86400 -j DROP

    # 7. Dynamic Service Ports
    for p in "${TCP_PORTS[@]}"; do iptables -A INPUT -p tcp --dport $p -j ACCEPT; done
    for p in "${UDP_PORTS[@]}"; do iptables -A INPUT -p udp --dport $p -j ACCEPT; done

    # 8. Invalid States (f and o)
    iptables -A FORWARD -m state --state INVALID -j LOG --log-prefix "Forward Invalid Drop: " --log-level 4
    iptables -A FORWARD -m state --state INVALID -j DROP
    iptables -A OUTPUT -m state --state INVALID -j LOG --log-prefix "OUTPUT Invalid Drop: " --log-level 4
    iptables -A OUTPUT -m state --state INVALID -j DROP

    # 9. Final Forward Portscan Check
    iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
    iptables -A FORWARD -m recent --name portscan --remove

    # 10. Policies
    iptables -A INPUT -j REJECT
    ip6tables -A INPUT -j DROP
    iptables -A OUTPUT -j ACCEPT
    iptables -A FORWARD -j REJECT

    iptables-save > $STEALTH_PATH
    echo "[+] Rules applied based on spreadsheet logic."
}

purge_red() {
    echo "First Time RED?" | wall
    TRUSTED_REGEX=$(echo $WHITELIST_IPS "127.0.0.1" | sed 's/ /|/g')
    ACTIVE_IPS=$(ss -ntu | awk '{print $6}' | cut -d: -f1 | sort -u | grep -v "Address")

    for ip in $ACTIVE_IPS; do
        if [[ ! $ip =~ ^($TRUSTED_REGEX)$ ]]; then
            ss -K dst $ip
            echo "[!] Kicked: $ip"
        fi
    done
    echo "[+] Purge complete."
}

recall() {
    [[ -f "$STEALTH_PATH" ]] && iptables-restore < $STEALTH_PATH && echo "[+] Rules Restored." || echo "[-] No backup."
}

while true; do
    show_menu
    read choice
    case $choice in
        1) iptables -L -n -v --line-numbers ;;
        2) set_ips ;;
        3) set_ports ;;
        4) apply_rules ;;
        5) purge_red ;;
        6) recall ;;
        7) exit 0 ;;
    esac
done
