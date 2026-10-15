#!/bin/bash
# ==========================================================================
# LINUX NETFILTER / IPTABLES 5G DEFENSE SCRIPT
# Generated: 2026-10-15 22:44:14
# Deployed at: 5G UPF (User Plane Function) N3/N6 Network Interface
# ==========================================================================
set -e

echo '[+] Initializing 5G UPF Netfilter Firewall Rules...'

# 1. Create or flush custom NWDAF chain
iptables -N 5G_NWDAF_FILTER 2>/dev/null || iptables -F 5G_NWDAF_FILTER

# 2. Allow established and related connections (performance optimization)
iptables -A 5G_NWDAF_FILTER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Mitigation for SYNScan: 5G-NIDD SYN Port Scanning probe with abnormal TTL
iptables -A 5G_NWDAF_FILTER -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m ttl --ttl-lt 58 -j LOG --log-prefix '[5G-ALERT-SYNScan] '
iptables -A 5G_NWDAF_FILTER -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m ttl --ttl-lt 58 -j DROP

# Mitigation for TCPDoSTargeted: High-rate targeted TCP flood exhausting 5G UPF session table
iptables -A 5G_NWDAF_FILTER -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m ttl --ttl-lt 64 -j LOG --log-prefix '[5G-ALERT-TCPDoSTargeted] '
iptables -A 5G_NWDAF_FILTER -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m ttl --ttl-lt 64 -j DROP

# Mitigation for UDPFlood: Volumetric UDP flood targeting 5G SIP/DNS infrastructure
iptables -A 5G_NWDAF_FILTER -p udp -m limit --limit 50/sec -j ACCEPT
iptables -A 5G_NWDAF_FILTER -p udp -j DROP

# Mitigation for PortScan: Reconnaissance scan probing well-known 5G service ports
iptables -A 5G_NWDAF_FILTER -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m ttl --ttl-lt 50 -j LOG --log-prefix '[5G-ALERT-PortScan] '
iptables -A 5G_NWDAF_FILTER -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m ttl --ttl-lt 50 -j DROP

# 3. Default forward rule
iptables -A 5G_NWDAF_FILTER -j ACCEPT
iptables -D FORWARD -i eth0 -j 5G_NWDAF_FILTER 2>/dev/null || true
iptables -I FORWARD 1 -i eth0 -j 5G_NWDAF_FILTER

echo '[+] 5G Firewall rules successfully enforced at kernel level!'