#!/bin/bash
# ==============================================================================
# AEGIS-OVERLORD: SOVEREIGN EDITION (The Absolute Final King)
# ==============================================================================

# --- CONFIG & INTEL ---
INTEL_DIR="/tmp/.aegis_intel" ; mkdir -p $INTEL_DIR
LOG_MAIN="$INTEL_DIR/main.log"
VAULT="/dev/shm/.vault" ; mkdir -p $VAULT
DASHBOARD="./aegis_overlord.html"
BINARIES=("/bin/ls" "/bin/ps" "/bin/netstat" "/usr/bin/whoami" "/bin/ss" "/usr/bin/top")

# --- 1. THE VAULT (Binary Integrity) ---
shield_binaries() {
    for bin in "${BINARIES[@]}"; do
        if [ -f "$bin" ]; then
            sha256sum "$bin" > "$VAULT/$(basename "$bin").hash"
            cp "$bin" "$VAULT/$(basename "$bin").clean"
        fi
    done
}

enforce_integrity() {
    for bin in "${BINARIES[@]}"; do
        [ ! -f "$bin" ] && cp "$VAULT/$(basename "$bin").clean" "$bin"
        curr_h=$(sha256sum "$bin"); clean_h=$(cat "$VAULT/$(basename "$bin").hash" 2>/dev/null)
        if [ "$curr_h" != "$clean_h" ]; then
            cp "$VAULT/$(basename "$bin").clean" "$bin" ; chmod +x "$bin"
            echo "[$(date +%T)] 🚨 BINARY REVERTED: $bin" >> $LOG_MAIN
        fi
    done
}

# --- 2. THE SENTINEL (Detection & Mitigation) ---
monitor_system() {
    # Fileless Malware (memfd)
    find /proc/*/exe -ls 2>/dev/null | grep -E "memfd|\(deleted\)" | while read -r line; do
        bad_pid=$(echo "$line" | awk '{print $11}' | cut -d/ -f3)
        echo "[$(date +%T)] ☣️ MALWARE KILLED: PID $bad_pid" >> $LOG_MAIN
        kill -9 "$bad_pid" 2>/dev/null
    done

    # Hidden Process Detection
    ps_pids=$(/dev/shm/.vault/ps.clean -eo pid --no-headers)
    for p_dir in /proc/[0-9]*; do
        pid=${p_dir##*/}
        if ! echo "$ps_pids" | grep -q -w "$pid"; then
            echo "[$(date +%T)] 💀 GHOST KILLED: $(cat $p_dir/comm) ($pid)" >> $LOG_MAIN
            kill -9 "$pid" 2>/dev/null
        fi
    done
}

# --- 3. THE TUI (Interactive Dashboard) ---
run_tui() {
    while true; do
        clear
        echo -e "\033[1;36m👑 AEGIS OVERLORD: SOVEREIGN\033[0m"
        echo -e "----------------------------------------------------"
        echo -e " [L] NET LOCKDOWN  [P] PURGE PERSIST  [I] IMMUTABLE ON"
        echo -e " [S] SUID GUARD    [B] RE-SCAN BINS   [Q] EXIT"
        echo -e "----------------------------------------------------"
        echo -e "\033[1;33mDETECTION FEED (Arrows to scroll in 2nd tab):\033[0m"
        tail -n 12 $LOG_MAIN | tac
        echo -ne "\n\033[1;32mCommand > \033[0m"
        read -n 1 -t 3 key
        case "$key" in
            l|L) iptables -P INPUT DROP; iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT ;;
            p|P) find /home -name "authorized_keys" -exec truncate -s 0 {} \; ; echo "" > /etc/crontab ;;
            i|I) chattr +i /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null ;;
            s|S) find / -perm -4000 -type f -exec chmod 000 {} \; 2>/dev/null ;;
            b|B) shield_binaries ;;
            q|Q) pkill -P $$; exit ;;
        esac
    done
}

# --- 4. THE GUI (Web Quadrant) ---
generate_gui() {
    cat <<EOF > $DASHBOARD
    <html><head><meta http-equiv="refresh" content="2"><style>
    body { background: #0d1117; color: #c9d1d9; font-family: monospace; padding: 20px; }
    .box { background: #161b22; border: 1px solid #30363d; padding: 10px; margin-bottom: 10px; border-left: 4px solid #58a6ff; }
    .alert { border-left-color: #ff7b72; background: #211a1d; }
    </style></head><body>
    <h1>🛡️ AEGIS SOVEREIGN GUI</h1>
    $(tail -n 30 $LOG_MAIN | tac | sed 's/🚨\(.*\)/<div class="box alert"><b>[TAMPER]<\/b>\1<\/div>/' | sed 's/☣️\(.*\)/<div class="box alert"><b>[MALWARE]<\/b>\1<\/div>/' | sed 's/\[\(.*\)\]\(.*\)/<div class="box"><b>[\1]<\/b>\2<\/div>/')
</body></html>
EOF
    chmod 666 $DASHBOARD
}

# --- EXECUTION ---
if [[ $EUID -ne 0 ]]; then echo "Run as root!"; exit 1; fi
shield_binaries
(while true; do enforce_integrity; monitor_system; generate_gui; sleep 3; done) &
run_tui
