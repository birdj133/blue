#!/bin/bash
# ==============================================================================
# AEGIS-SOLO: STANDALONE DEFENDER (No Scoring IP Required)
# ==============================================================================

LOG_FILE="/tmp/.aegis_local.log"
DASHBOARD="./aegis_dashboard.html"
MY_IP=$(hostname -I | awk '{print $1}' | cut -d' ' -f1)

# --- COLORS ---
RED='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
BLU='\033[1;34m'
NC='\033[0m'

# Check for Root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: You must run this as sudo.${NC}"
   exit 1
fi

# --- 1. NETWORK SHIELDING (General Hardening) ---
apply_network_shield() {
    echo -e "${BLU}[*] Applying General Anti-Flood Shielding...${NC}"
    iptables -F
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Rate limit connections (Basic protection)
    iptables -A INPUT -p tcp --syn --dport 22 -m connlimit --connlimit-above 5 -j REJECT
    iptables -A INPUT -p tcp --syn -m limit --limit 20/s --limit-burst 30 -j ACCEPT
    echo "[$(date +%T)] 🛡️ SHIELD: General DoS protection active." >> $LOG_FILE
}

# --- 2. THE GUARDIAN ENGINE ---
guardian_engine() {
    exec -a "[kworker/u2:1-evict]" bash << 'EOF' &
    LOG_FILE="/tmp/.aegis_local.log"
    DASHBOARD="./aegis_dashboard.html"
    SERVICES=$(systemctl list-units --type=service --state=running | awk '{print $1}' | grep ".service")

    while true; do
        # A. C2 & SOCKET DETECTION
        for pid_path in /proc/[0-9]*; do
            pid=${pid_path##*/}
            [ -e "$pid_path/fd/0" ] || continue
            fd0=$(readlink "$pid_path/fd/0" 2>/dev/null)
            
            if [[ "$fd0" == socket:* ]]; then
                inode=${fd0#socket:[}; inode=${inode%]}
                rem_ip=$(grep "$inode" /proc/net/tcp 2>/dev/null | awk '{print $3}' | cut -d: -f1)
                
                # If remote IP is detected and not local (00000000)
                if [[ ! -z "$rem_ip" && "$rem_ip" != "00000000" ]]; then
                    proc_name=$(cat "$pid_path/comm" 2>/dev/null)
                    # Honey-Talk
                    echo -e "\nCRITICAL: IO Error. Connection Reset.\n" > "/proc/$pid/fd/1" 2>/dev/null
                    kill -9 "$pid"
                    echo "[$(date +%T)] 💀 KILLED C2: $proc_name (PID $pid)" >> $LOG_FILE
                fi
            fi
        done

        # B. SERVICE HEALING
        for srv in $SERVICES; do
            if [[ $(systemctl is-active "$srv") != "active" ]]; then
                systemctl start "$srv"
                echo "[$(date +%T)] 🛠️ HEALED: $srv restarted." >> $LOG_FILE
            fi
        done

        # C. DASHBOARD GENERATION
        cat <<EOD > $DASHBOARD
<html><head><meta http-equiv="refresh" content="1"><style>
    body { background: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; padding: 25px; }
    .card { background: #161b22; border-left: 5px solid #30363d; padding: 15px; margin-bottom: 10px; border-radius: 4px; }
    .c2 { border-left-color: #f7768e; background: #211a1d; }
    .heal { border-left-color: #79c0ff; }
</style></head><body>
    <h2 style="color:#58a6ff">🛡️ AEGIS SOLO: DASHBOARD</h2>
    $(tail -n 20 $LOG_FILE | tac | sed 's/💀\(.*\)/<div class="card c2"><b>[ALERT]<\/b> \1<\/div>/' | sed 's/🛠️\(.*\)/<div class="card heal"><b>[RECOVERED]<\/b> \1<\/div>/')
</body></html>
EOD
        sleep 2
    done
EOF
}

# --- 3. WATCHDOG ---
spawn_watchdog() {
    while true; do
        if ! pgrep -f "[kworker/u2:1-evict]" > /dev/null; then
            guardian_engine
        fi
        sleep 2
    done
}

# --- EXECUTION ---
clear
echo -e "${GRN}[+] Aegis Solo Standalone Starting...${NC}"
touch $LOG_FILE
apply_network_shield
guardian_engine
spawn_watchdog &
echo -e "${GRN}[+] Dashboard: file://$(realpath $DASHBOARD)${NC}"
tail -f $LOG_FILE
