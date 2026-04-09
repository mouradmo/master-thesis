import json
import subprocess
import sys
from collections import defaultdict
from ipaddress import ip_address, ip_network

PCAP = sys.argv[1] if len(sys.argv) > 1 else "54831_dump.pcap"

PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]


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


def extract_dns_names():
    out = run_tshark([
        "-Y", "dns.flags.response == 0 and dns.qry.name",
        "-T", "fields",
        "-e", "dns.qry.name",
        "-E", "separator=,",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ])

    names = []
    seen = set()

    for line in out.splitlines():
        name = line.strip().lower().rstrip(".")
        if not name:
            continue

        # Skip obvious local discovery noise
        if name in {"wpad", "wpad.local"}:
            continue
        if name.endswith(".local"):
            continue

        if name not in seen:
            seen.add(name)
            names.append(name)

    return names


def infer_role(ip):
    if ip in {"8.8.8.8", "8.8.4.4"}:
        return "external_dns"
    if ip.endswith(".1"):
        return "gateway_or_dns"
    if ip.startswith("224.") or ip.startswith("239."):
        return "multicast"
    if ip.endswith(".255"):
        return "broadcast"
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return "internal_host"
    return "external_host"


def is_private_ip(ip):
    addr = ip_address(ip)
    return any(addr in net for net in PRIVATE_NETWORKS)


def classify_for_sim(role, ip):
    if role in {"multicast", "broadcast"}:
        return "ignore"
    if role == "gateway_or_dns":
        return "gateway"
    if is_private_ip(ip):
        return "internal"
    return "external"


def build_simulated_topology(host_rows, edge_rows, dns_names):
    internal_hosts = []
    external_hosts = []
    gateway_hosts = []
    ignored_hosts = []

    for host in host_rows:
        ip = host["ip"]
        role = host["role"]
        sim_type = classify_for_sim(role, ip)

        item = {
            "original_ip": ip,
            "original_role": role,
            "sim_type": sim_type,
        }

        if sim_type == "internal":
            internal_hosts.append(item)
        elif sim_type == "external":
            external_hosts.append(item)
        elif sim_type == "gateway":
            gateway_hosts.append(item)
        else:
            ignored_hosts.append(item)

    mapping_hosts = []
    ignored_ips = {item["original_ip"] for item in ignored_hosts}

    for i, host in enumerate(sorted(internal_hosts, key=lambda x: x["original_ip"]), start=1):
        mapping_hosts.append({
            **host,
            "zone": "A",
            "service_name": f"A_internal_host_{i:02d}",
        })

    for i, host in enumerate(sorted(external_hosts, key=lambda x: x["original_ip"]), start=1):
        zone = chr(ord("B") + i - 1)
        mapping_hosts.append({
            **host,
            "zone": zone,
            "service_name": f"{zone}_external_host_01",
        })

    for host in gateway_hosts:
        mapping_hosts.append({
            **host,
            "zone": "A",
            "service_name": "gw",
        })

    service_by_ip = {
        item["original_ip"]: item["service_name"]
        for item in mapping_hosts
    }

    filtered_edges = []
    for edge in edge_rows:
        src = edge["src"]
        dst = edge["dst"]

        if src in ignored_ips or dst in ignored_ips:
            continue

        filtered_edges.append({
            "src_original_ip": src,
            "dst_original_ip": dst,
            "src_service": service_by_ip.get(src),
            "dst_service": service_by_ip.get(dst),
            "packet_count": edge["packet_count"],
            "protocols": edge["protocols"],
        })

    zone_labels = ["A"] + [chr(ord("B") + i) for i in range(len(external_hosts))]
    hosts_per_zone = [len(internal_hosts)] + [1] * len(external_hosts)

    simulated_topology = {
        "pcap_file": PCAP,
        "zones": len(zone_labels),
        "zone_labels": zone_labels,
        "hosts_per_zone": hosts_per_zone,
        "dns_names": dns_names,
        "mapping": mapping_hosts,
        "ignored_hosts": ignored_hosts,
        "edges": filtered_edges,
        "notes": [
            "Zone A contains internal hosts.",
            "Each external host is placed in its own zone.",
            "Gateway/DNS-like infrastructure is represented by service 'gw'.",
            "Broadcast and multicast addresses are ignored for topology replication.",
            "dns_names contains extracted DNS query names from the PCAP."
        ]
    }

    with open("simulated_topology.json", "w") as f:
        json.dump(simulated_topology, f, indent=2)

    print("Wrote simulated_topology.json")
    print(f"zones={simulated_topology['zones']}")
    print("hosts_per_zone=" + ",".join(map(str, simulated_topology["hosts_per_zone"])))
    print(f"dns_names={len(simulated_topology['dns_names'])}")


def main():
    hosts, edges = extract_packets()
    dns_names = extract_dns_names()

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

    topology = {
        "pcap_file": PCAP,
        "hosts": host_rows,
        "edges": edge_rows,
        "dns_names": dns_names,
    }

    with open("topology.json", "w") as f:
        json.dump(topology, f, indent=2)

    print("Wrote topology.json")
    print(f"dns_names={len(dns_names)}")

    build_simulated_topology(host_rows, edge_rows, dns_names)


if __name__ == "__main__":
    main()