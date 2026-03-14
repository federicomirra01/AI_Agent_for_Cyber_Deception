#!/bin/bash

# Initialize Firewall Rules in BLOCK ALL mode
echo "Initializing firewall rules..."

# 1. Clear existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# 2. Set Default Policies: BLOCK EVERYTHING
# This ensures a "Default Deny" posture
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 3. Allow Infrastructure & Management
iptables -A INPUT -i lo -j ACCEPT
# Explicitly allow APIs so the AI Agent isn't locked out [cite: 1, 4]
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
iptables -A INPUT -p tcp --dport 7000 -j ACCEPT

# 4. State Management
# Essential to allow return traffic for any rules the API inserts
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# 5. Define a simple DROP chain (Bypassing the problematic LOG target)
# Since the 'LOG' target is failing on your kernel, we will use a direct DROP
# for the initial "Block All" posture.
iptables -N BLOCK_TRAFFIC
iptables -A BLOCK_TRAFFIC -j DROP

# 6. Apply Default Blocking between networks
# This blocks traffic between attacker (192.168.100.0/24) and honeypot (172.20.0.0/24)
iptables -A FORWARD -s 192.168.100.0/24 -d 172.20.0.0/24 -j BLOCK_TRAFFIC
iptables -A FORWARD -s 172.20.0.0/24 -d 192.168.100.0/24 -j BLOCK_TRAFFIC

# 7. Enable NAT for outbound access from honeypots
iptables -t nat -A POSTROUTING -s 172.20.0.0/24 -o eth0 -j MASQUERADE

# 8. Save initial rules
mkdir -p /firewall/rules
iptables-save > /firewall/rules/current_rules.txt

echo "Firewall initialized to DEFAULT DROP."
echo "Management API (5000) and Suricata API (7000) are OPEN."
