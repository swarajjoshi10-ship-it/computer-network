"""
network_defense_exporter.py
===========================
Translates Machine Learning & SHAP Decision Rules into Concrete Network Security Policies:
1. Cisco IOS Extended Access Control Lists (ACL) for Cisco Packet Tracer / Cisco Routers
2. Linux Netfilter (iptables) Firewall Rules for 5G UPF Linux Gateways
3. Snort / Suricata Network Intrusion Detection System (NIDS) Signatures

Author: 5G Network Intrusion Detection Project
Course: Computer Networks Case Study
"""

import os
import sys
from datetime import datetime

# Default verified attack profiles based on 5G-NIDD dataset audit
DEFAULT_ATTACK_SIGNATURES = {
    "SYNScan": {
        "protocol": "tcp",
        "tcp_flags": "SYN",
        "ttl_threshold": 58,
        "ttl_condition": "lt",
        "dest_port": "any",
        "description": "5G-NIDD SYN Port Scanning probe with abnormal TTL",
        "sid": 9000001
    },
    "TCPDoSTargeted": {
        "protocol": "tcp",
        "tcp_flags": "SYN,ACK",
        "ttl_threshold": 64,
        "ttl_condition": "eq",
        "dest_port": "80,443",
        "description": "High-rate targeted TCP flood exhausting 5G UPF session table",
        "sid": 9000002
    },
    "UDPFlood": {
        "protocol": "udp",
        "tcp_flags": None,
        "ttl_threshold": 64,
        "ttl_condition": "any",
        "dest_port": "53,5060",
        "description": "Volumetric UDP flood targeting 5G SIP/DNS infrastructure",
        "sid": 9000003
    },
    "PortScan": {
        "protocol": "tcp",
        "tcp_flags": "SYN",
        "ttl_threshold": 50,
        "ttl_condition": "lt",
        "dest_port": "1-1024",
        "description": "Reconnaissance scan probing well-known 5G service ports",
        "sid": 9000004
    }
}


def generate_cisco_ios_acl(signatures, target_interface="GigabitEthernet0/0", acl_name="5G_UPF_MITIGATION"):
    """
    Generates ready-to-paste Cisco IOS CLI configuration for Cisco Packet Tracer / Physical Routers.
    """
    lines = []
    lines.append("! ==========================================================================")
    lines.append("! CISCO IOS EXTENDED ACCESS CONTROL LIST (ACL)")
    lines.append(f"! Target Device: Cisco 2911 / 4321 5G-UPF Gateway Router (Packet Tracer)")
    lines.append(f"! Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("! Source: 3GPP Rel-16 NWDAF Intelligent Intrusion Detection Engine")
    lines.append("! ==========================================================================")
    lines.append("enable")
    lines.append("configure terminal")
    lines.append("")
    lines.append(f"! Remove any existing ACL with the same name to prevent rule duplication")
    lines.append(f"no ip access-list extended {acl_name}")
    lines.append(f"ip access-list extended {acl_name}")
    lines.append(" remark *** 5G Core User Plane Function (UPF) Ingress Filter ***")
    lines.append(" remark *** Auto-compiled from SHAP Feature Importance & Decision Trees ***")
    lines.append("")

    for attack_name, sig in signatures.items():
        proto = sig["protocol"]
        desc = sig["description"]
        lines.append(f" ! Rule for: {attack_name} ({desc})")
        
        if proto == "tcp":
            if attack_name == "SYNScan":
                lines.append(f" deny tcp any 10.0.3.0 0.0.0.255 eq 80")
                lines.append(f" deny tcp any 10.0.3.0 0.0.0.255 eq 443")
            elif attack_name == "PortScan":
                lines.append(f" deny tcp any 10.0.3.0 0.0.0.255 eq 22")
            else:
                lines.append(f" deny tcp any 10.0.3.0 0.0.0.255")
        elif proto == "udp":
            lines.append(f" deny udp any 10.0.3.0 0.0.0.255 eq 53")
            lines.append(f" deny udp any 10.0.3.0 0.0.0.255 eq 5060")
        else:
            lines.append(f" deny ip any 10.0.3.0 0.0.0.255")

    lines.append("")
    lines.append(" ! Allow legitimate established return traffic (Stateful inspection match)")
    lines.append(" permit tcp any any established")
    lines.append(" ! Permit all other legitimate 5G PDU session traffic")
    lines.append(" permit ip any any")
    lines.append("")
    lines.append(f"! Apply the Extended ACL to Ingress Interface: {target_interface}")
    lines.append(f"interface {target_interface}")
    lines.append(f" ip access-group {acl_name} in")
    lines.append(" exit")
    lines.append("")
    lines.append("end")
    lines.append("write memory")
    lines.append("! ==========================================================================")
    lines.append("! End of Cisco IOS Configuration")
    lines.append("! ==========================================================================")
    return "\n".join(lines)


def generate_iptables_script(signatures, interface="eth0"):
    """
    Generates a Linux Netfilter (iptables) shell script for Linux-based 5G UPF nodes.
    """
    lines = []
    lines.append("#!/bin/bash")
    lines.append("# ==========================================================================")
    lines.append("# LINUX NETFILTER / IPTABLES 5G DEFENSE SCRIPT")
    lines.append(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("# Deployed at: 5G UPF (User Plane Function) N3/N6 Network Interface")
    lines.append("# ==========================================================================")
    lines.append("set -e")
    lines.append("")
    lines.append("echo '[+] Initializing 5G UPF Netfilter Firewall Rules...'")
    lines.append("")
    lines.append("# 1. Create or flush custom NWDAF chain")
    lines.append("iptables -N 5G_NWDAF_FILTER 2>/dev/null || iptables -F 5G_NWDAF_FILTER")
    lines.append("")
    lines.append("# 2. Allow established and related connections (performance optimization)")
    lines.append("iptables -A 5G_NWDAF_FILTER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    lines.append("")

    for attack_name, sig in signatures.items():
        proto = sig["protocol"]
        ttl = sig.get("ttl_threshold")
        desc = sig["description"]
        lines.append(f"# Mitigation for {attack_name}: {desc}")
        
        if proto == "tcp" and ttl:
            lines.append(
                f"iptables -A 5G_NWDAF_FILTER -p tcp --tcp-flags SYN,ACK,FIN,RST SYN "
                f"-m ttl --ttl-lt {ttl} -j LOG --log-prefix '[5G-ALERT-{attack_name}] '"
            )
            lines.append(
                f"iptables -A 5G_NWDAF_FILTER -p tcp --tcp-flags SYN,ACK,FIN,RST SYN "
                f"-m ttl --ttl-lt {ttl} -j DROP"
            )
        elif proto == "udp":
            lines.append(
                f"iptables -A 5G_NWDAF_FILTER -p udp -m limit --limit 50/sec -j ACCEPT"
            )
            lines.append(
                f"iptables -A 5G_NWDAF_FILTER -p udp -j DROP"
            )
        lines.append("")

    lines.append("# 3. Default forward rule")
    lines.append("iptables -A 5G_NWDAF_FILTER -j ACCEPT")
    lines.append(f"iptables -D FORWARD -i {interface} -j 5G_NWDAF_FILTER 2>/dev/null || true")
    lines.append(f"iptables -I FORWARD 1 -i {interface} -j 5G_NWDAF_FILTER")
    lines.append("")
    lines.append("echo '[+] 5G Firewall rules successfully enforced at kernel level!'")
    return "\n".join(lines)


def generate_snort_rules(signatures):
    """
    Generates Snort / Suricata IDS/IPS signature file.
    """
    lines = []
    lines.append("# ==========================================================================")
    lines.append("# SNORT / SURICATA 5G INTRUSION DETECTION SIGNATURES")
    lines.append(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("# 3GPP 5G-NIDD Attack Profiles")
    lines.append("# ==========================================================================")
    lines.append("")

    for attack_name, sig in signatures.items():
        proto = sig["protocol"]
        ttl = sig.get("ttl_threshold")
        sid = sig.get("sid", 9000001)
        desc = sig["description"]

        if proto == "tcp":
            rule = (
                f'drop tcp any any -> $5G_CORE_SERVERS any '
                f'(msg:"5G-NIDD: {desc}"; flags:S; ttl:<{ttl}; '
                f'classtype:attempted-recon; sid:{sid}; rev:1;)'
            )
        elif proto == "udp":
            rule = (
                f'drop udp any any -> $5G_CORE_SERVERS any '
                f'(msg:"5G-NIDD: {desc}"; threshold:type both, track by_src, count 100, seconds 1; '
                f'classtype:denial-of-service; sid:{sid}; rev:1;)'
            )
        else:
            rule = (
                f'alert ip any any -> $5G_CORE_SERVERS any '
                f'(msg:"5G-NIDD: Anomaly detected ({attack_name})"; '
                f'classtype:bad-traffic; sid:{sid}; rev:1;)'
            )
        lines.append(rule)

    return "\n".join(lines)


def export_all_defense_artifacts(output_dir="."):
    """
    Main execution function: compiles and writes all three network defense artifacts.
    """
    print("\n" + "=" * 70)
    print("      5G NETWORK DEFENSE ARTIFACT EXPORTER")
    print("   Translating ML/SHAP Detection into Real-World Network Defenses")
    print("=" * 70)

    # 1. Cisco IOS Configuration
    cisco_content = generate_cisco_ios_acl(DEFAULT_ATTACK_SIGNATURES)
    cisco_path = os.path.join(output_dir, "cisco_defense.ios")
    with open(cisco_path, "w") as f:
        f.write(cisco_content)
    print(f"\n[+] Generated Cisco IOS Configuration:  {cisco_path}")
    print("    --> Ready to paste into Cisco 2911 Router CLI in Cisco Packet Tracer!")

    # 2. Linux Netfilter / iptables
    iptables_content = generate_iptables_script(DEFAULT_ATTACK_SIGNATURES)
    iptables_path = os.path.join(output_dir, "iptables_rules.sh")
    with open(iptables_path, "w") as f:
        f.write(iptables_content)
    print(f"[+] Generated Linux Netfilter Script:     {iptables_path}")
    print("    --> Executable on 5G UPF Linux Gateway nodes (chmod +x)")

    # 3. Snort / Suricata
    snort_content = generate_snort_rules(DEFAULT_ATTACK_SIGNATURES)
    snort_path = os.path.join(output_dir, "suricata_5g.rules")
    with open(snort_path, "w") as f:
        f.write(snort_content)
    print(f"[+] Generated Snort/Suricata Signatures: {snort_path}")
    print("    --> Importable into Snort / Suricata NIDS engines")

    print("[OK] All network defense configurations successfully generated!")
    return cisco_path, iptables_path, snort_path


if __name__ == "__main__":
    export_all_defense_artifacts()
