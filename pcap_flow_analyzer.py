"""
pcap_flow_analyzer.py
=====================
Raw Binary PCAP Dissector and 5G Network Flow Extractor.

Demonstrates Core Computer Networks Foundations:
- Layer 2: Ethernet Frame parsing & EtherType identification
- Layer 3: IPv4 Header decoding (TTL, IP Header Length, Identification, Protocol)
- Layer 4: TCP Header flag dissection (SYN, ACK, RST, FIN) & UDP datagram parsing
- Network Flow Aggregation: Assembling raw packets into bidirectional 5-tuples
- Feature Extraction: Computes sTtl, dTtl, Dur, Rate, sMeanPktSz, and TCP State

Works natively with zero external dependencies (pure Python struct/socket engine)
and includes a built-in 5G traffic synthesizer for demonstration.

Author: 5G Network Intrusion Detection Project
Course: Computer Networks Case Study
"""

import os
import sys
import struct
import socket
import time
from collections import defaultdict


class PacketDissector:
    """Dissects raw binary network frames down to Layer 2, 3, and 4 fields."""

    @staticmethod
    def dissect_ethernet(data):
        """Dissects IEEE 802.3 / DIX Ethernet Frame (14 bytes)."""
        if len(data) < 14:
            return None, None, None
        dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", data[:14])
        dst_mac_str = ":".join(f"{b:02x}" for b in dst_mac)
        src_mac_str = ":".join(f"{b:02x}" for b in src_mac)
        payload = data[14:]
        return {"src_mac": src_mac_str, "dst_mac": dst_mac_str, "ethertype": hex(ethertype)}, payload, ethertype

    @staticmethod
    def dissect_ipv4(data):
        """Dissects RFC 791 IPv4 Header (minimum 20 bytes)."""
        if len(data) < 20:
            return None, None
        v_ihl, tos, total_len, identification, flags_frag, ttl, protocol, checksum, src_ip, dst_ip = struct.unpack(
            "!BBHHHBBH4s4s", data[:20]
        )
        version = v_ihl >> 4
        ihl = (v_ihl & 0x0F) * 4  # Internet Header Length in bytes
        flags = flags_frag >> 13
        frag_offset = flags_frag & 0x1FFF
        
        src_ip_str = socket.inet_ntoa(src_ip)
        dst_ip_str = socket.inet_ntoa(dst_ip)
        payload = data[ihl:total_len] if total_len > ihl else data[ihl:]

        header_dict = {
            "version": version,
            "ihl": ihl,
            "tos": tos,
            "total_len": total_len,
            "id": identification,
            "flags": flags,
            "ttl": ttl,
            "protocol": protocol,
            "checksum": checksum,
            "src_ip": src_ip_str,
            "dst_ip": dst_ip_str
        }
        return header_dict, payload

    @staticmethod
    def dissect_tcp(data):
        """Dissects RFC 793 TCP Header (minimum 20 bytes)."""
        if len(data) < 20:
            return None, None
        src_port, dst_port, seq, ack, offset_reserved, flags, window, checksum, urg_ptr = struct.unpack(
            "!HHIIBBHHH", data[:20]
        )
        data_offset = (offset_reserved >> 4) * 4

        # Dissect TCP Control Bits (Flags)
        tcp_flags = {
            "FIN": bool(flags & 0x01),
            "SYN": bool(flags & 0x02),
            "RST": bool(flags & 0x04),
            "PSH": bool(flags & 0x08),
            "ACK": bool(flags & 0x10),
            "URG": bool(flags & 0x20)
        }
        
        flag_strs = [name for name, active in tcp_flags.items() if active]
        flag_summary = ",".join(flag_strs) if flag_strs else "NONE"

        header_dict = {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "data_offset": data_offset,
            "flags": tcp_flags,
            "flag_summary": flag_summary,
            "window": window,
            "checksum": checksum
        }
        payload = data[data_offset:]
        return header_dict, payload

    @staticmethod
    def dissect_udp(data):
        """Dissects RFC 768 UDP Header (8 bytes)."""
        if len(data) < 8:
            return None, None
        src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
        header_dict = {
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "checksum": checksum
        }
        payload = data[8:length] if length > 8 else data[8:]
        return header_dict, payload


class FlowAggregator:
    """
    Aggregates individual packets into bidirectional network flows (5-tuples)
    and computes standard 5G-NIDD statistical flow features.
    """
    def __init__(self):
        self.flows = defaultdict(lambda: {
            "start_time": None,
            "last_time": None,
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": None,
            "fwd_packets": 0,
            "bwd_packets": 0,
            "fwd_bytes": 0,
            "bwd_bytes": 0,
            "fwd_ttl": [],
            "bwd_ttl": [],
            "fwd_pkt_sizes": [],
            "tcp_flags_seen": set(),
            "state": "INT"
        })

    def get_flow_key(self, ip_hdr, l4_hdr):
        """Returns standard bidirectional 5-tuple key."""
        proto = "TCP" if ip_hdr["protocol"] == 6 else ("UDP" if ip_hdr["protocol"] == 17 else "OTHER")
        src = (ip_hdr["src_ip"], l4_hdr["src_port"])
        dst = (ip_hdr["dst_ip"], l4_hdr["dst_port"])
        if src <= dst:
            return (src[0], dst[0], src[1], dst[1], proto, True)
        else:
            return (dst[0], src[0], dst[1], src[1], proto, False)

    def add_packet(self, timestamp, ip_hdr, l4_hdr, l4_type):
        key = self.get_flow_key(ip_hdr, l4_hdr)
        flow_id = key[:5]
        is_forward = key[5]

        flow = self.flows[flow_id]
        if flow["start_time"] is None:
            flow["start_time"] = timestamp
            flow["src_ip"] = ip_hdr["src_ip"] if is_forward else ip_hdr["dst_ip"]
            flow["dst_ip"] = ip_hdr["dst_ip"] if is_forward else ip_hdr["src_ip"]
            flow["src_port"] = l4_hdr["src_port"] if is_forward else l4_hdr["dst_port"]
            flow["dst_port"] = l4_hdr["dst_port"] if is_forward else l4_hdr["src_port"]
            flow["protocol"] = l4_type

        flow["last_time"] = timestamp

        pkt_len = ip_hdr["total_len"]
        if is_forward:
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += pkt_len
            flow["fwd_ttl"].append(ip_hdr["ttl"])
            flow["fwd_pkt_sizes"].append(pkt_len)
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += pkt_len
            flow["bwd_ttl"].append(ip_hdr["ttl"])

        if l4_type == "TCP":
            flags = l4_hdr["flags"]
            if flags["SYN"]:
                flow["tcp_flags_seen"].add("SYN")
            if flags["ACK"]:
                flow["tcp_flags_seen"].add("ACK")
            if flags["FIN"]:
                flow["tcp_flags_seen"].add("FIN")
            if flags["RST"]:
                flow["tcp_flags_seen"].add("RST")

            # Determine TCP Connection State machine
            if "SYN" in flow["tcp_flags_seen"] and "ACK" in flow["tcp_flags_seen"] and "FIN" in flow["tcp_flags_seen"]:
                flow["state"] = "FIN"
            elif "SYN" in flow["tcp_flags_seen"] and "ACK" in flow["tcp_flags_seen"]:
                flow["state"] = "CON"  # Established
            elif "RST" in flow["tcp_flags_seen"]:
                flow["state"] = "RST"  # Abrupt reset / rejected scan
            elif "SYN" in flow["tcp_flags_seen"]:
                flow["state"] = "REQ"  # Half-open SYN probe (Typical SYNScan)
        else:
            flow["state"] = "INT"  # Stateless UDP

    def export_feature_records(self):
        """Converts internal flows into tabular records matching 5G-NIDD schema."""
        records = []
        for flow_id, data in self.flows.items():
            duration = max(0.0001, data["last_time"] - data["start_time"])
            tot_pkts = data["fwd_packets"] + data["bwd_packets"]
            tot_bytes = data["fwd_bytes"] + data["bwd_bytes"]
            rate = tot_pkts / duration
            s_mean_sz = sum(data["fwd_pkt_sizes"]) / len(data["fwd_pkt_sizes"]) if data["fwd_pkt_sizes"] else 0
            s_ttl = data["fwd_ttl"][0] if data["fwd_ttl"] else 64
            d_ttl = data["bwd_ttl"][0] if data["bwd_ttl"] else 0

            records.append({
                "Flow": f"{data['src_ip']}:{data['src_port']} -> {data['dst_ip']}:{data['dst_port']}",
                "Proto": data["protocol"],
                "sTtl": s_ttl,
                "dTtl": d_ttl,
                "Dur": round(duration, 4),
                "Rate": round(rate, 2),
                "sMeanPktSz": round(s_mean_sz, 1),
                "TotPkts": tot_pkts,
                "TotBytes": tot_bytes,
                "State": data["state"]
            })
        return records


def parse_pcap_file(filepath):
    """
    Parses a standard Libpcap (.pcap) file in pure Python.
    Format specification:
    Global Header: 24 bytes (Magic, Major, Minor, Thiszone, Sigfigs, Snaplen, Network)
    Packet Header: 16 bytes (ts_sec, ts_usec, incl_len, orig_len)
    """
    if not os.path.exists(filepath):
        print(f"[-] PCAP file not found: {filepath}")
        return []

    print(f"\n[+] Opening PCAP: {filepath}")
    with open(filepath, "rb") as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            print("[-] Invalid PCAP header.")
            return []

        magic = struct.unpack("!I", global_header[:4])[0]
        # Standard libpcap magic numbers: 0xa1b2c3d4 (big endian) or 0xd4c3b2a1 (little endian)
        is_little_endian = (magic == 0xd4c3b2a1)
        endian_char = "<" if is_little_endian else "!"

        aggregator = FlowAggregator()
        packet_count = 0

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian_char}IIII", pkt_hdr)
            timestamp = ts_sec + (ts_usec / 1_000_000.0)
            raw_pkt = f.read(incl_len)

            packet_count += 1
            eth_hdr, ip_payload, ethertype = PacketDissector.dissect_ethernet(raw_pkt)
            if ethertype != 0x0800:
                continue  # Skip non-IPv4 frames (e.g. ARP, IPv6)

            ip_hdr, l4_payload = PacketDissector.dissect_ipv4(ip_payload)
            if not ip_hdr:
                continue

            proto_num = ip_hdr["protocol"]
            if proto_num == 6:  # TCP
                tcp_hdr, _ = PacketDissector.dissect_tcp(l4_payload)
                if tcp_hdr:
                    aggregator.add_packet(timestamp, ip_hdr, tcp_hdr, "TCP")
            elif proto_num == 17:  # UDP
                udp_hdr, _ = PacketDissector.dissect_udp(l4_payload)
                if udp_hdr:
                    aggregator.add_packet(timestamp, ip_hdr, udp_hdr, "UDP")

    print(f"[+] Successfully dissected {packet_count} raw network packets.")
    return aggregator.export_feature_records()


def synthesize_sample_5g_pcap(filepath="sample_5g_traffic.pcap"):
    """
    Synthesizes a compliant .pcap file containing simulated 5G UPF traffic:
    1. Legitimate 5G PDU Web Session (10.0.1.10 -> 10.0.3.100:80, Full Handshake)
    2. SYNScan Port Reconnaissance Attack (10.0.1.99 -> 10.0.3.100, Low TTL=48, Half-open REQ)
    3. Volumetric UDP Flood Attack (10.0.1.99 -> 10.0.3.100:53, High Rate)
    """
    print(f"\n[+] Synthesizing sample 5G PCAP file: {filepath}...")
    with open(filepath, "wb") as f:
        # 1. Global PCAP Header (24 bytes)
        # Magic: 0xa1b2c3d4, Version 2.4, Zone 0, Sigfigs 0, Snaplen 65535, LinkType 1 (Ethernet)
        f.write(struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

        base_time = time.time()

        def make_ipv4_packet(src_ip, dst_ip, proto, ttl, l4_data):
            ihl = 5
            total_len = 20 + len(l4_data)
            ip_hdr = struct.pack(
                "!BBHHHBBH4s4s",
                (4 << 4) | ihl, 0, total_len, 1001, 0x4000, ttl, proto, 0,
                socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
            )
            eth_hdr = struct.pack("!6s6sH", b"\x00\x11\x22\x33\x44\x55", b"\x66\x77\x88\x99\xaa\xbb", 0x0800)
            return eth_hdr + ip_hdr + l4_data

        def write_frame(pkt_data, offset_sec):
            t = base_time + offset_sec
            sec = int(t)
            usec = int((t - sec) * 1_000_000)
            hdr = struct.pack("!IIII", sec, usec, len(pkt_data), len(pkt_data))
            f.write(hdr + pkt_data)

        # Flow A: Benign 3-way handshake + HTTP Request
        # 1. SYN
        tcp_syn = struct.pack("!HHIIBBHHH", 49201, 80, 1000, 0, (5 << 4), 0x02, 64240, 0, 0)
        write_frame(make_ipv4_packet("10.0.1.10", "10.0.3.100", 6, 64, tcp_syn), 0.001)
        # 2. SYN-ACK
        tcp_synack = struct.pack("!HHIIBBHHH", 80, 49201, 5000, 1001, (5 << 4), 0x12, 64240, 0, 0)
        write_frame(make_ipv4_packet("10.0.3.100", "10.0.1.10", 6, 64, tcp_synack), 0.003)
        # 3. ACK
        tcp_ack = struct.pack("!HHIIBBHHH", 49201, 80, 1001, 5001, (5 << 4), 0x10, 64240, 0, 0)
        write_frame(make_ipv4_packet("10.0.1.10", "10.0.3.100", 6, 64, tcp_ack), 0.005)

        # Flow B: Malicious SYNScan (Attacker scans ports 22, 23, 8080 with Low TTL=48, never replies to SYN-ACK)
        for i, target_port in enumerate([22, 23, 8080]):
            tcp_probe = struct.pack("!HHIIBBHHH", 55000 + i, target_port, 2000, 0, (5 << 4), 0x02, 1024, 0, 0)
            write_frame(make_ipv4_packet("10.0.1.99", "10.0.3.100", 6, 48, tcp_probe), 0.020 + (i * 0.005))

        # Flow C: UDP Flood (High rate stateless UDP packets)
        for i in range(15):
            udp_data = struct.pack("!HHHH", 58000, 53, 8 + 64, 0) + (b"X" * 64)
            write_frame(make_ipv4_packet("10.0.1.99", "10.0.3.100", 17, 64, udp_data), 0.050 + (i * 0.001))

    print(f"[OK] Created synthetic 5G PCAP file: {filepath}")
    return filepath


def main():
    print("=" * 80)
    print("   5G-NIDD PCAP WIRE DISSECTOR & FLOW FEATURE EXTRACTOR")
    print("   Layer 2 Ethernet -> Layer 3 IPv4 -> Layer 4 TCP/UDP State Machine")
    print("=" * 80)

    pcap_path = "sample_5g_traffic.pcap"
    if not os.path.exists(pcap_path):
        synthesize_sample_5g_pcap(pcap_path)

    flow_records = parse_pcap_file(pcap_path)

    print("\n" + "=" * 80)
    print("              EXTRACTED 5G BIDIRECTIONAL FLOW FEATURES (5G-NIDD FORMAT)")
    print("=" * 80)
    fmt = "{:<32} {:<6} {:<6} {:<6} {:<8} {:<10} {:<10} {:<6}"
    print(fmt.format("FLOW 5-TUPLE", "PROTO", "sTtl", "dTtl", "Dur(s)", "Rate(p/s)", "MeanSz", "STATE"))
    print("-" * 80)

    for rec in flow_records:
        print(fmt.format(
            rec["Flow"],
            rec["Proto"],
            rec["sTtl"],
            rec["dTtl"],
            f"{rec['Dur']:.4f}",
            f"{rec['Rate']:.1f}",
            f"{rec['sMeanPktSz']:.1f}",
            rec["State"]
        ))

    print("-" * 80)
    print(f"[OK] Extracted {len(flow_records)} network flows ready for 5G Intrusion Detection inference.")
    print("=" * 80)


if __name__ == "__main__":
    main()
