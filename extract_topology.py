#!/usr/bin/env python3
import json
import subprocess
import sys
from collections import defaultdict
from ipaddress import ip_address, ip_network

PCAP = sys.argv[1]

PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]

A_OCTET2_BASE = 30
A_SERVER_OCTET3 = 10
HOST_OCTET3_START = 11
GW_HOST_OCTET4 = 254
MAX_ZONES = 26
MAX_HOSTS_PER_ZONE = 200

INTERNAL_DNS_IP = "172.30.10.53"
INTERNAL_DNS_GW = "172.30.10.254"


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
        "-Y", "dns.flags.response == 0 and ip.src and ip.dst and dns.qry.name",
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

        if name not in seen:
            seen.add(name)
            names.append(name)

    return names


def extract_dns_server_ips():
    """
    Detect DNS server IPs from observed DNS traffic behavior.

    We treat as DNS servers:
    - destinations of DNS queries
    - sources of DNS responses
    """
    dns_ips = set()

    out = run_tshark([
        "-Y", "dns.flags.response == 0 and ip.src and ip.dst",
        "-T", "fields",
        "-e", "ip.dst",
        "-E", "separator=,",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ])
    for line in out.splitlines():
        ip = line.strip()
        if ip:
            dns_ips.add(ip)

    out = run_tshark([
        "-Y", "dns.flags.response == 1 and ip.src and ip.dst",
        "-T", "fields",
        "-e", "ip.src",
        "-E", "separator=,",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ])
    for line in out.splitlines():
        ip = line.strip()
        if ip:
            dns_ips.add(ip)

    return dns_ips


def is_private_ip(ip):
    addr = ip_address(ip)
    return any(addr in net for net in PRIVATE_NETWORKS)


def infer_role(ip, dns_server_ips):
    if ip.startswith("224.") or ip.startswith("239."):
        return "multicast"

    if ip.endswith(".255"):
        return "broadcast"

    if ip in dns_server_ips and not is_private_ip(ip):
        return "external_dns"

    if ip.endswith(".1"):
        return "gateway_or_dns"

    if is_private_ip(ip):
        return "internal_host"

    return "external_host"


def classify_for_sim(role, ip):
    # Important: do not map broadcast/multicast to fake hosts
    if role == "broadcast":
        return "ignore"
    if role == "multicast":
        return "ignore"

    if role == "gateway_or_dns":
        return "gateway"

    if role == "external_dns":
        return "infra_dns"

    if is_private_ip(ip):
        return "internal"

    return "external"


def zone_to_octet2(zone):
    return A_OCTET2_BASE + (ord(zone) - ord("A"))


def build_host_subnet_ips(zone, host_index):
    """
    Host index 1 -> subnet third octet 11 -> host ip .11 / gw .254
    Host index 2 -> subnet third octet 12 -> host ip .12 / gw .254
    """
    if host_index < 1 or host_index > MAX_HOSTS_PER_ZONE:
        raise ValueError(f"host_index must be between 1 and {MAX_HOSTS_PER_ZONE}")

    o2 = zone_to_octet2(zone)
    o3 = HOST_OCTET3_START + (host_index - 1)
    return f"172.{o2}.{o3}.{o3}", f"172.{o2}.{o3}.{GW_HOST_OCTET4}"


def build_gateway_sim_ip():
    o2 = zone_to_octet2("A")
    o3 = A_SERVER_OCTET3
    return f"172.{o2}.{o3}.{GW_HOST_OCTET4}"


def external_zone_labels():
    return [chr(c) for c in range(ord("B"), ord("Z") + 1)]


def assign_external_hosts(external_hosts):
    """
    Distribute generic external hosts across zones B..Z using round-robin.
    Each zone can hold many hosts, up to MAX_HOSTS_PER_ZONE.
    """
    zones = external_zone_labels()
    total_capacity = len(zones) * MAX_HOSTS_PER_ZONE

    if len(external_hosts) > total_capacity:
        raise ValueError(
            f"Too many external hosts ({len(external_hosts)}). "
            f"Current topology supports at most {total_capacity} external hosts."
        )

    zone_host_counts = {z: 0 for z in zones}
    assigned = []

    for idx, host in enumerate(sorted(external_hosts, key=lambda x: x["original_ip"])):
        zone = zones[idx % len(zones)]
        zone_host_counts[zone] += 1
        host_index = zone_host_counts[zone]

        simulated_ip, gateway_ip = build_host_subnet_ips(zone, host_index)
        assigned.append({
            **host,
            "zone": zone,
            "service_name": f"{zone}_external_host_{host_index:02d}",
            "simulated_ip": simulated_ip,
            "gateway_ip": gateway_ip,
        })

    return assigned, zone_host_counts


def build_simulated_topology(host_rows, edge_rows, dns_names):
    internal_hosts = []
    external_hosts = []
    gateway_hosts = []
    external_dns_hosts = []
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
        elif sim_type == "infra_dns":
            external_dns_hosts.append(item)
        elif sim_type == "ignore":
            ignored_hosts.append(item)

    mapping_hosts = []

    # Internal hosts -> Zone A
    internal_zone_count = 0
    for host in sorted(internal_hosts, key=lambda x: x["original_ip"]):
        internal_zone_count += 1
        simulated_ip, gateway_ip = build_host_subnet_ips("A", internal_zone_count)
        mapping_hosts.append({
            **host,
            "zone": "A",
            "service_name": f"A_internal_host_{internal_zone_count:02d}",
            "simulated_ip": simulated_ip,
            "gateway_ip": gateway_ip,
        })

    # Generic external hosts -> distributed across B..Z
    external_assigned, external_zone_count_map = assign_external_hosts(external_hosts)
    mapping_hosts.extend(external_assigned)

    # Gateway-like hosts
    for host in sorted(gateway_hosts, key=lambda x: x["original_ip"]):
        mapping_hosts.append({
            **host,
            "zone": "A",
            "service_name": "gw",
            "simulated_ip": build_gateway_sim_ip(),
            "gateway_ip": "",
        })

    # All detected external DNS IPs -> one internal DNS service
    for host in sorted(external_dns_hosts, key=lambda x: x["original_ip"]):
        mapping_hosts.append({
            **host,
            "zone": "A",
            "service_name": "dns",
            "simulated_ip": INTERNAL_DNS_IP,
            "gateway_ip": INTERNAL_DNS_GW,
        })

    service_by_ip = {
        item["original_ip"]: item["service_name"]
        for item in mapping_hosts
    }

    simulated_ip_by_original_ip = {
        item["original_ip"]: item["simulated_ip"]
        for item in mapping_hosts
    }

    filtered_edges = []
    for edge in edge_rows:
        src = edge["src"]
        dst = edge["dst"]

        filtered_edges.append({
            "src_original_ip": src,
            "dst_original_ip": dst,
            "src_service": service_by_ip.get(src),
            "dst_service": service_by_ip.get(dst),
            "src_simulated_ip": simulated_ip_by_original_ip.get(src),
            "dst_simulated_ip": simulated_ip_by_original_ip.get(dst),
            "packet_count": edge["packet_count"],
            "protocols": edge["protocols"],
        })

    # Build actual zone list and counts
    zone_labels = ["A"]
    hosts_per_zone = [internal_zone_count]

    for zone in external_zone_labels():
        count = external_zone_count_map[zone]
        if count > 0:
            zone_labels.append(zone)
            hosts_per_zone.append(count)

    simulated_topology = {
        "pcap_file": PCAP,
        "zones": len(zone_labels),
        "zone_labels": zone_labels,
        "hosts_per_zone": hosts_per_zone,
        # "dns_names": dns_names,
        "mapping": mapping_hosts,
        "ignored_hosts": ignored_hosts,
        "edges": filtered_edges,
    }

    with open("simulated_topology.json", "w") as f:
        json.dump(simulated_topology, f, indent=2)

    print("Wrote simulated_topology.json")
    print(f"zones={simulated_topology['zones']}")
    print("zone_labels=" + ",".join(simulated_topology["zone_labels"]))
    print("hosts_per_zone=" + ",".join(map(str, simulated_topology["hosts_per_zone"])))
    # print(f"dns_names={len(simulated_topology['dns_names'])}")
    print(f"mapping_entries={len(simulated_topology['mapping'])}")
    print(f"ignored_hosts={len(simulated_topology['ignored_hosts'])}")


def main():
    hosts, edges = extract_packets()

    # dns_names = extract_dns_names()
    # dns_server_ips = extract_dns_server_ips()

    dns_names = []
    dns_server_ips = set()

    host_rows = []
    for ip in sorted(hosts):
        host_rows.append({
            "ip": ip,
            "role": infer_role(ip, dns_server_ips),
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
        # "dns_names": dns_names,
        # "dns_server_ips": sorted(dns_server_ips),
    }

    with open("topology.json", "w") as f:
        json.dump(topology, f, indent=2)

    print("Wrote topology.json")
    # print(f"dns_names={len(dns_names)}")
    # print(f"dns_server_ips={len(dns_server_ips)}")

    build_simulated_topology(host_rows, edge_rows, dns_names)


if __name__ == "__main__":
    main()