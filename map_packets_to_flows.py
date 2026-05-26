#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path
from scapy.all import IP, TCP, UDP, rdpcap, ICMP


def pkt_proto(p):
    if TCP in p:
        return "tcp"
    if UDP in p:
        return "udp"
    if ICMP in p:
        return "icmp"
    return str(p[IP].proto)


def pkt_ports(p):
    if TCP in p:
        return str(p[TCP].sport), str(p[TCP].dport)
    if UDP in p:
        return str(p[UDP].sport), str(p[UDP].dport)
    if ICMP in p:
        return str(int(p[ICMP].type)), str(int(p[ICMP].code))
    return "", ""


def norm_key(proto, src, sport, dst, dport):
    a = (src, str(sport))
    b = (dst, str(dport))
    return (proto, *a, *b) if a <= b else (proto, *b, *a)


def packet_flow_key(p):
    sport, dport = pkt_ports(p)
    return norm_key(pkt_proto(p), p[IP].src, sport, p[IP].dst, dport)


def zeek_flow_key(row):
    return norm_key(
        row.get("proto", ""),
        row.get("id.orig_h", ""),
        row.get("id.orig_p", ""),
        row.get("id.resp_h", ""),
        row.get("id.resp_p", ""),
    )


def fnum(x, default=None):
    try:
        if x in ("", "-", None):
            return default
        return float(x)
    except Exception:
        return default


def in_flow_time(pkt_time, flow, slack):
    ts = flow["ts_float"]
    dur = flow["duration_float"]

    if ts is None:
        return True

    # Zeek duration may be "-" for single-packet or unfinished flows.
    end = ts if dur is None else ts + max(0.0, dur)

    return (ts - slack) <= pkt_time <= (end + slack)


def choose_best(pkt_time, matches, slack):
    candidates = [m for m in matches if in_flow_time(pkt_time, m, slack)]

    if not candidates:
        return []

    # Prefer smallest time distance from flow start.
    candidates.sort(
        key=lambda m: abs(pkt_time - (m["ts_float"] if m["ts_float"] is not None else pkt_time))
    )

    return [candidates[0]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--flows", required=True, help="zeek/labeled_conn.csv")
    ap.add_argument("--out", default="packet_flow_map.csv")
    ap.add_argument("--time-slack", type=float, default=1.0)
    ap.add_argument("--all-candidates", action="store_true")
    args = ap.parse_args()

    flows = {}

    with open(args.flows, newline="", encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f), start=1):
            key = zeek_flow_key(row)
            flow = {
                "flow_row": i,
                "uid": row.get("uid", ""),
                "label": row.get("label", ""),
                "sample_id": row.get("sample_id", ""),
                "ts": row.get("ts", ""),
                "duration": row.get("duration", ""),
                "ts_float": fnum(row.get("ts")),
                "duration_float": fnum(row.get("duration")),
            }
            flows.setdefault(key, []).append(flow)

    rows = []

    for packet_no, p in enumerate(rdpcap(args.pcap), start=1):
        if IP not in p:
            continue

        key = packet_flow_key(p)
        pkt_time = float(p.time)
        matches = flows.get(key, [])

        if args.all_candidates:
            chosen = [m for m in matches if in_flow_time(pkt_time, m, args.time_slack)]
        else:
            chosen = choose_best(pkt_time, matches, args.time_slack)

        base = {
            "packet_no": packet_no,
            "packet_time": pkt_time,
            "packet_src": p[IP].src,
            "packet_dst": p[IP].dst,
            "proto": key[0],
            "src_port": key[2],
            "dst_port": key[4],
        }

        if chosen:
            for m in chosen:
                out = {k: v for k, v in m.items() if not k.endswith("_float")}
                rows.append({**base, **out})
        else:
            rows.append({
                **base,
                "flow_row": "",
                "uid": "",
                "label": "unmatched",
                "sample_id": "",
                "ts": "",
                "duration": "",
            })

    fieldnames = [
        "packet_no", "packet_time", "packet_src", "packet_dst",
        "proto", "src_port", "dst_port",
        "flow_row", "uid", "label", 
        "sample_id", "ts", "duration",
    ]

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"[+] Wrote packet-flow map: {args.out}")
    print(f"[+] Rows: {len(rows)}")


if __name__ == "__main__":
    main()