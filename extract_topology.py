#!/usr/bin/env python3
import json
import subprocess
import sys
from collections import defaultdict
from ipaddress import ip_address, ip_network

PCAP = sys.argv[1]

PRIVATE_NETWORKS = tuple(map(ip_network, [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]))

A_OCTET2_BASE = 30
A_SERVER_OCTET3 = 10
HOST_OCTET3_START = 11
GW_HOST_OCTET4 = 254
MAX_HOSTS_PER_ZONE = 200

INTERNAL_DNS_IP = "172.30.10.53"
INTERNAL_DNS_GW = "172.30.10.254"


def run_tshark(args):
    return subprocess.run(
        ["tshark", "-r", PCAP] + args,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def tshark_fields(display_filter, *fields):
    args = []
    if display_filter:
        args += ["-Y", display_filter]
    args += ["-T", "fields"]
    for f in fields:
        args += ["-e", f]
    args += ["-E", "separator=,", "-E", "quote=n", "-E", "occurrence=f"]
    return run_tshark(args)


def extract_packets():
    out = tshark_fields(None, "ip.src", "ip.dst", "_ws.col.Protocol")
    hosts = set()
    edges = defaultdict(lambda: {"count": 0, "protocols": set()})

    for line in out.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue

        src, dst, proto = parts[:3]
        if not src or not dst:
            continue

        hosts.update((src, dst))
        edges[(src, dst)]["count"] += 1
        if proto:
            edges[(src, dst)]["protocols"].add(proto)

    return hosts, edges


def extract_dns_names():
    out = tshark_fields(
        "dns.flags.response == 0 and ip.src and ip.dst and dns.qry.name",
        "dns.qry.name",
    )

    names, seen = [], set()
    for line in out.splitlines():
        name = line.strip().lower().rstrip(".")
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def extract_dns_server_ips():
    dns_ips = set()

    for flt, field in [
        ("dns.flags.response == 0 and ip.src and ip.dst", "ip.dst"),
        ("dns.flags.response == 1 and ip.src and ip.dst", "ip.src"),
    ]:
        out = tshark_fields(flt, field)
        dns_ips.update(line.strip() for line in out.splitlines() if line.strip())

    return dns_ips


def is_private_ip(ip):
    addr = ip_address(ip)
    return any(addr in net for net in PRIVATE_NETWORKS)


def infer_role(ip, dns_server_ips):
    if ip.startswith(("224.", "239.")):
        return "multicast"
    if ip.endswith(".255"):
        return "broadcast"
    if ip in dns_server_ips and not is_private_ip(ip):
        return "external_dns"
    if ip.endswith(".1"):
        return "gateway_or_dns"
    return "internal_host" if is_private_ip(ip) else "external_host"


def classify_for_sim(role, ip):
    if role in {"broadcast", "multicast"}:
        return "ignore"
    if role == "gateway_or_dns":
        return "gateway"
    if role == "external_dns":
        return "infra_dns"
    return "internal" if is_private_ip(ip) else "external"


def zone_to_octet2(zone):
    return A_OCTET2_BASE + ord(zone) - ord("A")


def build_host_subnet_ips(zone, host_index):
    if not 1 <= host_index <= MAX_HOSTS_PER_ZONE:
        raise ValueError(f"host_index must be between 1 and {MAX_HOSTS_PER_ZONE}")

    o2 = zone_to_octet2(zone)
    o3 = HOST_OCTET3_START + host_index - 1
    return f"172.{o2}.{o3}.{o3}", f"172.{o2}.{o3}.{GW_HOST_OCTET4}"


def build_gateway_sim_ip():
    return f"172.{zone_to_octet2('A')}.{A_SERVER_OCTET3}.{GW_HOST_OCTET4}"


def external_zone_labels():
    return [chr(c) for c in range(ord("B"), ord("Z") + 1)]


def assign_external_hosts(external_hosts):
    zones = external_zone_labels()
    total_capacity = len(zones) * MAX_HOSTS_PER_ZONE

    if len(external_hosts) > total_capacity:
        raise ValueError(
            f"Too many external hosts ({len(external_hosts)}). "
            f"Current topology supports at most {total_capacity} external hosts."
        )

    zone_host_counts = {z: 0 for z in zones}
    assigned = []

    for i, host in enumerate(sorted(external_hosts, key=lambda x: x["original_ip"])):
        zone = zones[i % len(zones)]
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
    grouped = {
        "internal": [],
        "external": [],
        "gateway": [],
        "infra_dns": [],
        "ignore": [],
    }

    for host in host_rows:
        ip = host["ip"]
        sim_type = classify_for_sim(host["role"], ip)
        grouped[sim_type].append({
            "original_ip": ip,
            "original_role": host["role"],
            "sim_type": sim_type,
        })

    mapping = []

    for i, host in enumerate(sorted(grouped["internal"], key=lambda x: x["original_ip"]), start=1):
        simulated_ip, gateway_ip = build_host_subnet_ips("A", i)
        mapping.append({
            **host,
            "zone": "A",
            "service_name": f"A_internal_host_{i:02d}",
            "simulated_ip": simulated_ip,
            "gateway_ip": gateway_ip,
        })
    internal_count = len(grouped["internal"])

    external_assigned, external_zone_count_map = assign_external_hosts(grouped["external"])
    mapping.extend(external_assigned)

    for host in sorted(grouped["gateway"], key=lambda x: x["original_ip"]):
        mapping.append({
            **host,
            "zone": "A",
            "service_name": "gw",
            "simulated_ip": build_gateway_sim_ip(),
            "gateway_ip": "",
        })

    for host in sorted(grouped["infra_dns"], key=lambda x: x["original_ip"]):
        mapping.append({
            **host,
            "zone": "A",
            "service_name": "dns",
            "simulated_ip": INTERNAL_DNS_IP,
            "gateway_ip": INTERNAL_DNS_GW,
        })

    service_by_ip = {m["original_ip"]: m["service_name"] for m in mapping}
    sim_ip_by_ip = {m["original_ip"]: m["simulated_ip"] for m in mapping}

    filtered_edges = [{
        "src_original_ip": edge["src"],
        "dst_original_ip": edge["dst"],
        "src_service": service_by_ip.get(edge["src"]),
        "dst_service": service_by_ip.get(edge["dst"]),
        "src_simulated_ip": sim_ip_by_ip.get(edge["src"]),
        "dst_simulated_ip": sim_ip_by_ip.get(edge["dst"]),
        "packet_count": edge["packet_count"],
        "protocols": edge["protocols"],
    } for edge in edge_rows]

    zone_labels = ["A"]
    hosts_per_zone = [internal_count]
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
        "mapping": mapping,
        "ignored_hosts": grouped["ignore"],
        "edges": filtered_edges,
    }

    with open("simulated_topology.json", "w") as f:
        json.dump(simulated_topology, f, indent=2)

    print("Wrote simulated_topology.json")
    print(f"zones={simulated_topology['zones']}")
    print("zone_labels=" + ",".join(zone_labels))
    print("hosts_per_zone=" + ",".join(map(str, hosts_per_zone)))
    print(f"mapping_entries={len(mapping)}")
    print(f"ignored_hosts={len(grouped['ignore'])}")


def main():
    hosts, edges = extract_packets()

    # Enable these later if needed
    # dns_names = extract_dns_names()
    # dns_server_ips = extract_dns_server_ips()
    dns_names = []
    dns_server_ips = set()

    host_rows = [{"ip": ip, "role": infer_role(ip, dns_server_ips)} for ip in sorted(hosts)]

    edge_rows = [{
        "src": src,
        "dst": dst,
        "packet_count": info["count"],
        "protocols": sorted(info["protocols"]),
    } for (src, dst), info in sorted(edges.items())]

    topology = {
        "pcap_file": PCAP,
        "hosts": host_rows,
        "edges": edge_rows,
    }

    with open("topology.json", "w") as f:
        json.dump(topology, f, indent=2)

    print("Wrote topology.json")
    build_simulated_topology(host_rows, edge_rows, dns_names)


if __name__ == "__main__":
    main()