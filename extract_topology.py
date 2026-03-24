import csv
import json
import subprocess
import sys
from collections import defaultdict

PCAP = sys.argv[1] if len(sys.argv) > 1 else "54831_dump.pcap"

def run_tshark(args):
    result = subprocess.run(
        ["tshark", "-r", PCAP] + args,
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout

def extract_packets():
    out = run_tshark([
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-E", "separator=,",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ])

    edges = defaultdict(lambda: {"count": 0, "protocols": set()})
    hosts = set()

    for line in out.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue

        src, dst, proto = parts[0], parts[1], parts[2]

        if not src or not dst:
            continue

        hosts.add(src)
        hosts.add(dst)

        key = (src, dst)
        edges[key]["count"] += 1
        if proto:
            edges[key]["protocols"].add(proto)

    return hosts, edges

def infer_role(ip):
    if ip == "8.8.8.8" or ip == "8.8.4.4":
        return "external_dns"
    if ip.endswith(".1"):
        return "gateway_or_dns"
    if ip.startswith("224.") or ip.startswith("239."):
        return "multicast"
    if ip.endswith(".255"):
        return "broadcast"
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
        return "internal_host"
    return "external_host"

def main():
    hosts, edges = extract_packets()

    host_rows = []
    for ip in sorted(hosts):
        host_rows.append({
            "ip": ip,
            "role": infer_role(ip),
        })

    edge_rows = []
    for (src, dst), info in sorted(edges.items()):
        edge_rows.append({
            "src": src,
            "dst": dst,
            "packet_count": info["count"],
            "protocols": sorted(info["protocols"]),
        })

    with open("hosts.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "role"])
        writer.writeheader()
        writer.writerows(host_rows)

    with open("edges.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["src", "dst", "packet_count", "protocols"])
        writer.writeheader()
        for row in edge_rows:
            row = row.copy()
            row["protocols"] = ";".join(row["protocols"])
            writer.writerow(row)

    topology = {
        "hosts": host_rows,
        "edges": edge_rows,
    }

    with open("topology.json", "w") as f:
        json.dump(topology, f, indent=2)

    print("Wrote hosts.csv, edges.csv, topology.json")

if __name__ == "__main__":
    main()