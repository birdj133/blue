#!/bin/bash
# ==============================================================================
# AEGIS-SOLO: APEX EDITION
# The ultimate "Blue Team Prized Possession" for Linux Defense
# ==============================================================================

SCORING_IP=$1
LOG_FILE="/tmp/.aegis_local.log"
DASHBOARD="./aegis_dashboard.html"
MY_IP=$(hostname -I | awk '{print $1}')

# --- STYLING ---
RED='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
BLU='\033[1;34m'
NC='\033[0m'

if [[ -z "$SCORING_IP" ]]; then
    echo -e "${RED}[!] ERROR: Scoring IP required.${NC}"
    echo -e "Usage: sudo bash aegis.sh <SCORING_IP>"
    exit 1
fi

# --- 1. NETWORK SHIELDING (Anti-Flood/DoS) ---
apply_network_shield() {
    echo -e "${BLU}[*] Hardening Network Stack & Applying Anti-Flood...${NC}"
    # Reset and Prioritize Scoring Engine
    iptables -F
    iptables -A INPUT -s "$SCORING_IP" -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Connection Limiting (Per IP) to prevent service exhaustion
    iptables -A INPUT -p tcp --syn --dport 22 -m connlimit --connlimit-above 3 -j REJECT
    iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 15 -j REJECT
    
    # Drop SYN Floods & Invalid Packets
    iptables -A INPUT -p tcp --syn -m limit --limit 20/s --limit-burst 30 -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP
    iptables -m state --state INVALID -j DROP
}

# --- 2. THE GUARDIAN ENGINE (The Logic) ---
guardian_engine() {
    # Self-Masquerade in process list
    exec -a "[kworker/u2:1-evict]" bash << 'EOF' &
    SCORING_IP="'"$SCORING_IP"'"
    LOG_FILE="'"$LOG_FILE"'"
    DASHBOARD="'"$DASHBOARD"'"
    
    # Baseline active services for self-healing
    SERVICES=$(systemctl list-units --type=service --state=running | awk '{print $1}' | grep ".service")

    while true; do
        # A. C2 & SOCKET DETECTION (Direct Kernel FD Inspection)
        for pid_path in /proc/[0-9]*; do
            pid=${pid_path##*/}
            [ -e "$pid_path/fd/0" ] || continue
            fd0=$(readlink "$pid_path/fd/0" 2>/dev/null)
            
            if [[ "$fd0" == socket:* ]]; then
                inode=${fd0#socket:[}; inode=${inode%]}
                rem_ip=$(grep "$inode" /proc/net/tcp 2>/dev/null | awk '{print $3}' | cut -d: -f1)
                
                if [[ ! -z "$rem_ip" && "$rem_ip" != "00000000" && "$rem_ip" != "$SCORING_IP" ]]; then
                    proc_name=$(cat "$pid_path/comm" 2>/dev/null)
                    # DECEPTION: Honey-Talk Gaslighting
                    echo -e "\nCRITICAL: System integrity violation at 0x0045.\nTerminating session for emergency maintenance...\n" > "/proc/$pid/fd/1" 2>/dev/null
                    kill -9 "$pid"
                    echo "[$(date +%T)] 💀 KILLED C2: $proc_name (PID $pid) IP: $rem_ip" >> $LOG_FILE
                fi
            fi
        done

        # B. SERVICE SELF-HEALING
        for srv in $SERVICES; do
            if [[ $(systemctl is-active "$srv") != "active" ]]; then
                systemctl start "$srv"
                echo "[$(date +%T)] 🛠️ HEALED: $srv was down, forced restart." >> $LOG_FILE
            fi
        done

        # C. PERSISTENCE MONITORING
        find /etc/cron* /etc/systemd/system /home/*/.ssh/authorized_keys -mmin -1 -type f 2>/dev/null | while read -r line; do
            echo "[$(date +%T)] ⚠️ PERSISTENCE: Unauthorized change in $line" >> $LOG_FILE
        done

        # D. DASHBOARD GENERATION
        cat <<EOD > $DASHBOARD
<html><head><meta http-equiv="refresh" content="1"><style>
    body { background: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; padding: 25px; }
    .card { background: #161b22; border-left: 5px solid #30363d; padding: 15px; margin-bottom: 10px; border-radius: 4px; }
    .c2 { border-left-color: #f7768e; background: #211a1d; }
    .heal { border-left-color: #79c0ff; }
    .ts { color: #565f89; }
</style></head><body>
    <h2 style="color:#58a6ff">🛡️ AEGIS SOLO: APEX DEFENDER</h2>
    $(tail -n 20 $LOG_FILE | tac | sed 's/💀\(.*\)/<div class="card c2"><span class="ts">ALERT<\/span><br>\1<\/div>/' | sed 's/🛠️\(.*\)/<div class="card heal"><span class="ts">HEALING<\/span><br>\1<\/div>/' | sed 's/⚠️\(.*\)/<div class="card"><span class="ts">WARNING<\/span><br>\1<\/div>/')
</body></html>
EOD
        sleep 1
    done
EOF
}

# --- 3. WATCHDOG (The Dead Man's Switch) ---
spawn_watchdog() {
    while true; do
        if ! pgrep -f "[kworker/u2:1-evict]" > /dev/null; then
            guardian_engine
        fi
        sleep 1
    done
}

# --- EXECUTION ---
clear
echo -e "${GRN}----------------------------------------------------${NC}"
echo -e "${GRN}       AEGIS APEX: INITIALIZING DEFENSES            ${NC}"
echo -e "${GRN}----------------------------------------------------${NC}"

touch $LOG_FILE
# Apply Network Shielding
apply_network_shield
# Start the Guard
guardian_engine
# Start the Watchdog
spawn_watchdog &

echo -e "${GRN}[+] Aegis Active. Dashboard: file://$(realpath $DASHBOARD)${NC}"
tail -f $LOG_FILE
