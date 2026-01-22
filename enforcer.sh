#!/bin/bash

# =================================================================
# MASTER FIREWALL ENFORCER & KICKER (Universal Linux)
# =================================================================
# Features: 45s Sync, Auto-Kick, Systemd/Init.d Support, Panic Mode
# =================================================================

# 1. SETUP ENVIRONMENT & PATHS
IP_LIST="/etc/allowed_ips.txt"
ENFORCER_BIN="/usr/local/bin/ip_enforcer.sh"
PANIC_BIN="/usr/local/bin/panic.sh"
DASH_BIN="/usr/local/bin/fw-status.sh"

[[ $EUID -ne 0 ]] && echo "Error: Must run as root." && exit 1

echo "--- Initializing Universal Setup ---"

# 2. INSTALL DEPENDENCIES (Distro-Agnostic)
install_deps() {
    if command -v apt-get &>/dev/null; then
        apt-get update && apt-get install -y iptables conntrack curl
    elif command -v yum &>/dev/null; then
        yum install -y iptables conntrack-tools curl
    elif command -v apk &>/dev/null; then
        apk add iptables conntrack-tools curl
    fi
}
install_deps

# 3. CREATE THE DASHBOARD (Live View)
cat << 'EOF' > "$DASH_BIN"
#!/bin/bash
watch -n 1 "echo '--- CURRENT ALLOW-LIST (IPTABLES) ---'; \
            iptables -L ENFORCE_LIST -n | grep ACCEPT; \
            echo -e '\n--- RECENT KICKS/DROPS ---'; \
            dmesg | tail -n 15 | grep 'FW-KICK'"
EOF
chmod +x "$DASH_BIN"

# 4. CREATE THE PANIC SCRIPT (The Emergency Exit)
cat << EOF > "$PANIC_BIN"
#!/bin/bash
systemctl stop ip-enforcer 2>/dev/null
iptables -P INPUT ACCEPT
iptables -F
iptables -X
echo "!!! FIREWALL DISABED - ALL ACCESS OPENED !!!"
EOF
chmod +x "$PANIC_BIN"

# 5. CREATE THE MAIN ENFORCER (The 45s Heartbeat)
cat << 'EOF' > "$ENFORCER_BIN"
#!/bin/bash
IP_FILE="/etc/allowed_ips.txt"

# Ensure logging is enabled for the dashboard
sysctl -w net.netfilter.nf_conntrack_acct=1 2>/dev/null

while true; do
    # Create custom chain
    iptables -N ENFORCE_LIST 2>/dev/null || iptables -F ENFORCE_LIST
    
    # 1. Safety: Keep Established/Related connections for allowed IPs
    iptables -A ENFORCE_LIST -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # 2. Load and Apply Allow-List
    ALLOWED_IPS=""
    while IFS= read -r ip || [ -n "$ip" ]; do
        if [[ "$ip" =~ ^[0-9] ]]; then
            iptables -A ENFORCE_LIST -s "$ip" -j ACCEPT
            ALLOWED_IPS="${ALLOWED_IPS}${ip}|"
        fi
    done < "$IP_FILE"
    ALLOWED_IPS="${ALLOWED_IPS%|}"

    # 3. Apply the Hammer (Drop and Log everyone else)
    iptables -A ENFORCE_LIST -j LOG --log-prefix "FW-KICK: "
    iptables -A ENFORCE_LIST -j DROP

    # 4. Enforce Position 1 in INPUT chain
    iptables -D INPUT -j ENFORCE_LIST 2>/dev/null
    iptables -I INPUT 1 -j ENFORCE_LIST
    iptables -P INPUT DROP

    # 5. THE KICK: Sever existing connections for IPs not in list
    if [ -n "$ALLOWED_IPS" ]; then
        # Find active source IPs that are NOT in our allowed regex and kill them
        conntrack -L | grep "ESTABLISHED" | grep -vE "$ALLOWED_IPS" | awk '{print $4}' | cut -d "=" -f 2 | xargs -I {} conntrack -D -s {} 2>/dev/null
    fi

    sleep 45
done
EOF
chmod +x "$ENFORCER_BIN"

# 6. INITIALIZE ALLOW LIST (Add current user IP to prevent lockout)
if [ ! -f "$IP_LIST" ]; then
    USER_IP=$(who am i | awk '{print $5}' | sed 's/[()]//g')
    echo "127.0.0.1" > "$IP_LIST"
    [[ -n "$USER_IP" ]] && echo "$USER_IP" >> "$IP_LIST"
    echo "# Add one IP per line below" >> "$IP_LIST"
fi

# 7. PERSISTENCE SETUP
if command -v systemctl &>/dev/null; then
    cat << EOF > /etc/systemd/system/ip-enforcer.service
[Unit]
Description=Nuclear IP Enforcer and Kicker
After=network.target

[Service]
ExecStart=$ENFORCER_BIN
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ip-enforcer.service
    systemctl start ip-enforcer.service
else
    # Non-systemd: Add to crontab reboot
    (crontab -l 2>/dev/null; echo "@reboot $ENFORCER_BIN &") | crontab -
    nohup $ENFORCER_BIN >/dev/null 2>&1 &
fi

echo "-------------------------------------------------------"
echo "INSTALLATION COMPLETE"
echo "Dashboard: run 'fw-status.sh'"
echo "Panic Button: run 'panic.sh'"
echo "IP List: edit '/etc/allowed_ips.txt'"
echo "-------------------------------------------------------"
