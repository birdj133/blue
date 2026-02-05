#!/bin/bash

# --- 1. User Input for Whitelisting & Ports ---
read -p "Enter Whitelist IPs (comma-separated): " WHITELIST
read -p "Enter TCP Ports to open (comma-separated): " TCP_PORTS
read -p "Enter UDP Ports to open (comma-separated): " UDP_PORTS

# --- 2. Flush & Initial Setup ---
sudo iptables -F
sudo iptables -X
sudo ip6tables -F
sudo ip6tables -X

# --- 3. Whitelist (Infrastructure & Admin) ---
# Applies the provided IPs to both Source and Destination as per your original rules
IFS=',' read -ra ADDR <<< "$WHITELIST"
for ip in "${ADDR[@]}"; do
    sudo iptables -A INPUT -s $ip -j ACCEPT
    sudo iptables -A INPUT -d $ip -j ACCEPT
done

# --- 4. Bogon/Multicast Filtering ---
sudo iptables -A INPUT -s 224.0.0.0/4 -j DROP
sudo iptables -A INPUT -d 224.0.0.0/4 -j DROP
sudo iptables -A INPUT -s 240.0.0.0/5 -j DROP
sudo iptables -A INPUT -d 240.0.0.0/5 -j DROP
sudo iptables -A INPUT -s 0.0.0.0/8 -j DROP
sudo iptables -A INPUT -d 0.0.0.0/8 -j DROP
sudo iptables -A INPUT -s 239.255.255.0/24 -j DROP
sudo iptables -A INPUT -d 239.255.255.0/24 -j DROP
sudo iptables -A INPUT -s 255.255.255.255 -j DROP
sudo iptables -A INPUT -d 255.255.255.255 -j DROP

# --- 5. Logging & Rate Limiting ---
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-prefix "ICMP Attempt: " --log-level 4
sudo iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# --- 6. Honeyport & Portscan Detection (Forward/Input) ---
sudo iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:" --log-level 4
sudo iptables -A FORWARD -p tcp --dport 139 -m recent --name portscan --set -j DROP
sudo iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
sudo iptables -A INPUT -m recent --name portscan --remove

# --- 7. SSH Brute Force & Service Ports ---
sudo iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --set -j LOG --log-prefix "SSH ATTEMPT: " --log-level 4
sudo iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --rcheck --seconds 86400 -j DROP

# Open TCP Ports
IFS=',' read -ra T_PORTS <<< "$TCP_PORTS"
for port in "${T_PORTS[@]}"; do
    sudo iptables -A INPUT -p tcp --dport $port -j ACCEPT
done

# Open UDP Ports
IFS=',' read -ra U_PORTS <<< "$UDP_PORTS"
for port in "${U_PORTS[@]}"; do
    sudo iptables -A INPUT -p udp --dport $port -j ACCEPT
done

# --- 8. State Tracking & Invalid Packet Drops ---
sudo iptables -A FORWARD -m state --state INVALID -j LOG --log-prefix "Forward Invalid Drop: " --log-level 4
sudo iptables -A FORWARD -m state --state INVALID -j DROP
sudo iptables -A OUTPUT -m state --state INVALID -j LOG --log-prefix "OUTPUT Invalid Drop: " --log-level 4
sudo iptables -A OUTPUT -m state --state INVALID -j DROP

# Portscan cleanup in Forward
sudo iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
sudo iptables -A FORWARD -m recent --name portscan --remove

# --- 9. Final Policies & Save ---
sudo iptables -A INPUT -j REJECT
sudo iptables -A FORWARD -j REJECT
sudo iptables -A OUTPUT -j ACCEPT
sudo ip6tables -A INPUT -j DROP

sudo iptables-save | sudo tee /etc/iptables/rules.v4
sudo ip6tables-save | sudo tee /etc/iptables/rules.v6
