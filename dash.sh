#!/bin/bash

# --- STEALTH STORAGE ---
STEALTH_PATH="/usr/lib/.systemd-cache-auth"

# Variables initialization
JUMPBOX=""
SCORING=""
TEAMMATE=""
FRANCIA=""
OTHERS=""
TCP_PORTS=""
UDP_PORTS=""

show_menu() {
    echo -e "\n\e[1;31m!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\e[0m"
    echo -e "\e[1;31m   RED TEAM DEFENSE DASH      \e[0m"
    echo -e "\e[1;31m!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\e[0m"
    echo "1) LIST Rules (Screenshot Mode)"
    echo "2) SET IPs & Ports"
    echo "3) APPLY Spreadsheet Rules (Nuke & Pave)"
    echo "4) PURGE RED TEAM (Kick & Message)"
    echo "5) RECALL (Persistence)"
    echo "6) EXIT"
    echo -n "Select an option: "
}

enter_vars() {
    echo -e "\n--- [ WHITELIST INPUT ] ---"
    read -p "Jumpbox IP: " JUMPBOX
    read -p "Scoring Engine IP: " SCORING
    read -p "Teammate IP: " TEAMMATE
    read -p "Francias IP: " FRANCIA
    read -p "Other Trusted IPs: " OTHERS
    read -p "TCP Ports (comma separated): " TCP_PORTS
    read -p "UDP Ports (comma separated): " UDP_PORTS
    
    ALL_TRUSTED="$JUMPBOX,$SCORING,$TEAMMATE,$FRANCIA,$OTHERS"
    ALL_TRUSTED=$(echo $ALL_TRUSTED | sed 's/,,*/,/g; s/^,//; s/,$//')
    echo "[+] Variables saved."
}

apply_rules() {
    echo "[!] Cleaning tables and applying strict spreadsheet order..."
    
    # Reset
    iptables -P INPUT ACCEPT
    iptables -F
    iptables -X
    iptables -Z

    # 1. Whitelists (i and o)
    for ip in ${JUMPBOX} ${SCORING} ${TEAMMATE} ${FRANCIA} ${OTHERS}; do
        if [ ! -z "$ip" ]; then
            iptables -A INPUT -s $ip -j ACCEPT
            iptables -A OUTPUT -d $ip -j ACCEPT
        fi
    done

    # 2. Manual ICMP Scoring Rule
    iptables -A INPUT -s $SCORING -p icmp --icmp-type 8 -j ACCEPT

    # 3. Bogon Drops (i)
    for b in "224.0.0.0/4" "240.0.0.0/5" "0.0.0.0/8" "239.255.255.0/24" "255.255.255.255"; do
        iptables -A INPUT -s $b -j DROP
        iptables -A INPUT -d $b -j DROP
    done

    # 4. ICMP Logging
    iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-prefix "ICMP Attempt: " --log-level 4
    iptables -A INPUT -s 192.168.20.10 -p icmp --icmp-type 8 -j ACCEPT

    # 5. Honeypot (f)
    iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:" --log-level 4
    iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j DROP

    # 6. Flood Protection (i)
    iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
    iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
    iptables -A INPUT -m recent --name portscan --remove

    # 7. SSH Security
    iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --set -j LOG --log-prefix "SSH ATTEMPT: " --log-level 4
    if [ ! -z "$ALL_TRUSTED" ]; then
        iptables -A INPUT -p tcp --dport 22 -s $ALL_TRUSTED -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    fi
    iptables -A INPUT -p tcp -m recent --name sshattempt --rcheck --seconds 86400 -j DROP

    # 8. Service Ports
    IFS=',' read -ra ADDR <<< "$TCP_PORTS"
    for p in "${ADDR[@]}"; do iptables -A INPUT -p tcp --dport $p -j ACCEPT; done
    IFS=',' read -ra ADDR <<< "$UDP_PORTS"
    for p in "${ADDR[@]}"; do iptables -A INPUT -p udp --dport $p -j ACCEPT; done

    # 9. Invalid States (f and o) - RESTORED
    iptables -A FORWARD -m state --state INVALID -j LOG --log-prefix "Forward Invalid Drop: " --log-level 4
    iptables -A FORWARD -m state --state INVALID -j DROP
    iptables -A OUTPUT -m state --state INVALID -j LOG --log-prefix "OUTPUT Invalid Drop: " --log-level 4
    iptables -A OUTPUT -m state --state INVALID -j DROP

    # 10. Forward Portscan Re-check - RESTORED
    iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
    iptables -A FORWARD -m recent --name portscan --remove

    # 11. Final Policies
    iptables -A INPUT -j REJECT
    ip6tables -A INPUT -j DROP
    iptables -A OUTPUT -j ACCEPT
    iptables -A FORWARD -j REJECT

    # 12. Backup
    iptables-save > $STEALTH_PATH
    echo "[+] Applied successfully."
}

purge_red() {
    echo "First Time RED?" | wall
    # Terminates connections not matching whitelisted IPs
    for ip in ${JUMPBOX} ${SCORING} ${TEAMMATE} ${FRANCIA} ${OTHERS}; do
        if [ ! -z "$ip" ]; then
            ss -K dst != $ip
        fi
    done
    echo "[+] Purge complete."
}

recall() {
    if [ -f "$STEALTH_PATH" ]; then
        iptables-restore < $STEALTH_PATH
        echo "[+] Persistence Restored."
    else
        echo "[-] No stealth file found."
    fi
}

# Root Check
if [[ $EUID -ne 0 ]]; then
   echo "Use sudo!"
   exit 1
fi

while true; do
    show_menu
    read choice
    case $choice in
        1) iptables -L -n -v --line-numbers ;;
        2) enter_vars ;;
        3) apply_rules ;;
        4) purge_red ;;
        5) recall ;;
        6) exit 0 ;;
        *) echo "Invalid" ;;
    esac
done
