#!/usr/bin/env python3
import argparse       # CLI arguments parsing
import socket         # IP address conversion
import pandas as pd   # CSV + timestamps
import dpkt           # PCAP parsing
from dateutil import parser as dtparser

# # Convert raw IP bytes to dotted string
def ip_to_str(ip_bytes: bytes) -> str:
    return socket.inet_ntoa(ip_bytes)

# Load ground truth CSV
def parse_ground_truth(path: str) -> pd.DataFrame:
    gt = pd.read_csv(path, dtype=str).fillna("")
     # Parse UTC timestamps
    gt["start_dt"] = gt["start_time_utc"].apply(lambda x: dtparser.isoparse(x))
    gt["end_dt"]   = gt["end_time_utc"].apply(lambda x: dtparser.isoparse(x))

    # Normalize fields
    gt["protocol"] = gt["protocol"].str.lower().str.strip()
    gt["victim_port"] = gt["victim_port"].str.strip()

    return gt

# Extract protocol and ports
def packet_proto_ports(ip) -> tuple[str, str, str]:
    """
    Returns: (proto, sport, dport) as strings
    proto: 'tcp' | 'udp' | 'icmp' | 'other'
    sport/dport empty for non TCP/UDP
    """
    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        return "tcp", str(tcp.sport), str(tcp.dport)
    if isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        return "udp", str(udp.sport), str(udp.dport)
    if isinstance(ip.data, dpkt.icmp.ICMP):
        return "icmp", "", ""
    return "other", "", ""

def match_attack(gt: pd.DataFrame, pkt_dt, src_ip: str, dst_ip: str, proto: str, sport: str, dport: str):
   # Match packet to attack window
    for _, row in gt.iterrows():
        # Time window check
        if not (row["start_dt"] <= pkt_dt <= row["end_dt"]):
            continue
        # IP address check
        attacker = row["attacker_ip"].strip()
        victim = row["victim_ip"].strip()
        if attacker and not (src_ip == attacker or dst_ip == attacker):
            continue
        if victim and not (src_ip == victim or dst_ip == victim):
            continue
        # Protocol check
        req_proto = row["protocol"]
        if req_proto and req_proto != proto:
            continue
        # Port check
        req_port = row["victim_port"]
        if req_port:
            # accept if either direction matches
            if not (sport == req_port or dport == req_port):
                continue

        return row["attack_id"].strip(), row["attack_type"].strip()

    return "", "benign"

def main():
    # Parse CLI arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="Path to pcap file")
    ap.add_argument("--ground-truth", required=True, help="Path to ground_truth.csv")
    ap.add_argument("--out", required=True, help="Output CSV path")
    args = ap.parse_args()
    # Load ground truth
    gt = parse_ground_truth(args.ground_truth)

    rows = []
    with open(args.pcap, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            # Convert timestamp to UTC datetime
            pkt_dt = pd.to_datetime(ts, unit="s", utc=True).to_pydatetime()
            # Parse Ethernet/IP
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data

            # Extract packet features
            src_ip = ip_to_str(ip.src)
            dst_ip = ip_to_str(ip.dst)
            proto, sport, dport = packet_proto_ports(ip)

            attack_id, label = match_attack(gt, pkt_dt, src_ip, dst_ip, proto, sport, dport)

            rows.append({
                "timestamp_utc": pkt_dt.isoformat().replace("+00:00", "Z"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "src_port": sport,
                "dst_port": dport,
                "attack_id": attack_id,
                "label": label,
            })
    # Write output CSV
    df = pd.DataFrame(rows)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} labeled packets to {args.out}")

if __name__ == "__main__":
    main()
