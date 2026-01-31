#!/bin/bash
# Interactive firewall dashboard (matches original manual rule structure)

# --- Root Privilege Check ---
if [ "$EUID" -ne 0 ]; then
  whiptail --title "Permission Error" --msgbox "Please run as root (use sudo)." 10 45
  exit 1
fi

# --- Ensure whiptail exists ---
if ! command -v whiptail &>/dev/null; then
  echo "Installing whiptail..."
  apt-get update && apt-get install -y whiptail
fi

# --- Welcome message ---
whiptail --title "Firewall Setup" --msgbox "Welcome to the Interactive Firewall Setup Tool.\nUse ↑↓ to navigate, Enter to select." 12 60

# Variables
WHITELIST=""
SSH_ALLOW=""
PORTS=""

# --- FUNCTIONS ---

reset_firewall() {
  whiptail --title "Confirm Reset" --yesno "This will flush all rules and set all chains to ACCEPT.\nContinue?" 12 60
  if [[ $? -eq 0 ]]; then
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t mangle -F
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    whiptail --title "Firewall Reset" --msgbox "All rules cleared and policies set to ACCEPT." 10 60
  else
    whiptail --title "Cancelled" --msgbox "Firewall reset cancelled." 10 40
  fi
}

apply_rules() {
  # Flush existing rules first
  iptables -F
  iptables -X
  iptables -t nat -F
  iptables -t mangle -F

  # Default policies
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT

  # ------------- 1️⃣ WHITELIST -------------
  for ip in ${WHITELIST//,/ }; do
    [[ -n "$ip" ]] && iptables -A INPUT -s "$ip" -j ACCEPT
  done

  # ------------- 2️⃣ ALLOW ICMP FROM SCORING ENGINE -------------
  iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT

  # ------------- 3️⃣ DROP RESERVED / MULTICAST / BOGON RANGES -------------
  iptables -A INPUT -s 0.0.0.0/8 -j DROP
  iptables -A INPUT -d 0.0.0.0/8 -j DROP
  iptables -A INPUT -s 224.0.0.0/4 -j DROP
  iptables -A INPUT -s 224.0.0.9/8 -j DROP
  iptables -A INPUT -s 239.255.255.0/24 -j DROP
  iptables -A INPUT -s 255.255.255.255/5 -j DROP
  iptables -A INPUT -s 255.255.255.255/32 -j DROP

  # ------------- 4️⃣ ICMP LOGGING -------------
  iptables -A INPUT -p icmp --icmp-type echo-request -j LOG --log-prefix "ICMP Attempt: " --log-level 4

  # ------------- 5️⃣ PORTSCAN PROTECTION -------------
  iptables -A INPUT -p tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:" --log-level 4
  iptables -A INPUT -p tcp --dport 139 -m recent --name portscan --set -j DROP
  iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT
  iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP

  # ------------- 6️⃣ SSH ATTEMPT PROTECTION -------------
  iptables -A INPUT -p tcp --dport 22 -m recent --name sshattempt --set -j LOG --log-prefix "SSH ATTEMPT: " --log-level 4

  for ip in ${SSH_ALLOW//,/ }; do
    [[ -n "$ip" ]] && iptables -A INPUT -p tcp -s "$ip" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  done

  iptables -A INPUT -p tcp -m recent --name sshattempt --rcheck --seconds 86400 -j DROP

  # ------------- 7️⃣ ESTABLISHED RULE -------------
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # ------------- 8️⃣ USER-DEFINED PORT INPUTS -------------
  for port in ${PORTS//,/ }; do
    [[ -n "$port" ]] && iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
  done

  # ------------- 9️⃣ STATE + LOGGING CLEANUP -------------
  iptables -A INPUT -m state --state INVALID -j LOG --log-prefix "Invalid Drop: " --log-level 4
  iptables -A INPUT -m state --state INVALID -j DROP
  iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
  iptables -A INPUT -m recent --name portscan --remove

  # ------------- 🔚 FINAL REJECTS -------------
  iptables -A INPUT -j DROP

  # Save persistently
  if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save
  elif command -v service &>/dev/null; then
    service iptables save 2>/dev/null || echo "Could not save automatically."
  else
    iptables-save > /etc/iptables.rules
  fi

  whiptail --title "Firewall Applied" --msgbox "Firewall rules were applied successfully!" 10 60
}

# --- MENU LOOP ---
while true; do
  CHOICE=$(
    whiptail --title "Firewall Setup Dashboard" \
      --menu "Use ↑↓ to navigate and Enter to select an action:" 22 70 12 \
      "1" "View current iptables rules" \
      "2" "Set Whitelist IPs (comma separated)" \
      "3" "Set SSH Access IPs (comma separated)" \
      "4" "Set Allowed TCP Ports (comma separated)" \
      "5" "Preview configuration" \
      "6" "Apply rules and save" \
      "7" "Reset firewall to defaults" \
      "8" "Exit" 3>&2 2>&1 1>&3
  )

  case "$CHOICE" in
  1)
    iptables -L -v -n | whiptail --title "Current Firewall Rules" --scrolltext --textbox /dev/stdin 30 90
    ;;
  2)
    WHITELIST=$(whiptail --inputbox "Enter Whitelist IPs (comma-separated):" 10 70 "$WHITELIST" 3>&1 1>&2 2>&3)
    ;;
  3)
    SSH_ALLOW=$(whiptail --inputbox "Enter IPs allowed for SSH access (comma-separated):" 10 70 "$SSH_ALLOW" 3>&1 1>&2 2>&3)
    ;;
  4)
    PORTS=$(whiptail --inputbox "Enter Allowed TCP Ports (comma-separated):" 10 70 "$PORTS" 3>&1 1>&2 2>&3)
    ;;
  5)
    PREVIEW="Whitelist: $WHITELIST\nSSH Access: $SSH_ALLOW\nAllowed Ports: $PORTS"
    whiptail --title "Configuration Preview" --msgbox "$PREVIEW" 15 70
    ;;
  6)
    apply_rules
    ;;
  7)
    reset_firewall
    ;;
  8)
    whiptail --title "Exit Confirmation" --yesno "Are you sure you want to exit?" 10 50
    [[ $? -eq 0 ]] && break
    ;;
  esac
done
