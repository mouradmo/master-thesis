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

INTERNAL_ZONE = "A"
INTERNAL_OCTET2 = 30
EXTERNAL_START_OCTET2 = 31

A_SERVER_OCTET3 = 10
HOST_OCTET3_START = 11
HOST_OCTET3_END = 253
GW_HOST_OCTET4 = 254


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


def extract_dhcp_zero_owner():
    """
    DHCP Discover/Request usually use:

        0.0.0.0 -> 255.255.255.255

    Later DHCP Offer/ACK gives the real assigned address in bootp.yiaddr.

    This function maps the special source 0.0.0.0 to the real internal
    client IP, for example:

        0.0.0.0 belongs to 10.6.13.133

    The replay will still keep the packet source as 0.0.0.0, but it needs
    to know which container should replay those packets.
    """

    try:
        out = tshark_fields(
            "bootp and ip.src and ip.dst",
            "ip.src",
            "ip.dst",
            "bootp.id",
            "bootp.yiaddr",
        )
    except subprocess.CalledProcessError:
        return ""

    zero_xids = set()
    xid_to_yiaddr = {}

    for line in out.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 4:
            continue

        src, dst, xid, yiaddr = parts[:4]

        if not xid:
            continue

        if src == "0.0.0.0" and dst == "255.255.255.255":
            zero_xids.add(xid)

        if yiaddr and yiaddr != "0.0.0.0":
            xid_to_yiaddr[xid] = yiaddr

    for xid in sorted(zero_xids):
        owner = xid_to_yiaddr.get(xid, "")
        if owner:
            return owner

    return ""


def is_private_ip(ip):
    addr = ip_address(ip)
    return any(addr in net for net in PRIVATE_NETWORKS)


def infer_role(ip):
    if ip == "0.0.0.0":
        return "dhcp_zero"

    if ip.startswith(("224.", "239.")):
        return "multicast"

    if ip == "255.255.255.255" or ip.endswith(".255"):
        return "broadcast"


    return "internal_host" if is_private_ip(ip) else "external_host"


def classify_for_sim(role, ip):
    if role == "dhcp_zero":
        return "dhcp_zero"

    if role in {"broadcast", "multicast"}:
        return "ignore"

    return "internal" if is_private_ip(ip) else "external"


def zone_label(zone_index):
    if zone_index == 1:
        return "A"
    return f"Z{zone_index:04d}"


def build_internal_host_ips(host_index):
    """
    Internal:
      host 1 -> 172.30.11.11
      host 2 -> 172.30.12.12
    """

    o3 = HOST_OCTET3_START + host_index - 1

    if o3 > HOST_OCTET3_END:
        raise ValueError(
            f"Too many internal hosts. Current internal range supports "
            f"{HOST_OCTET3_END - HOST_OCTET3_START + 1} hosts."
        )

    simulated_ip = f"172.{INTERNAL_OCTET2}.{o3}.{o3}"
    gateway_ip = f"172.{INTERNAL_OCTET2}.{o3}.{GW_HOST_OCTET4}"

    return simulated_ip, gateway_ip


def build_external_host_ips(zone_index, host_index_in_zone):
    """
    External:
      Z0002 host 1 -> 172.31.11.11
      Z0002 host 2 -> 172.31.12.12

      Z0003 host 1 -> 172.32.11.11
      Z0003 host 2 -> 172.32.12.12
    """

    o2 = EXTERNAL_START_OCTET2 + (zone_index - 2)
    o3 = HOST_OCTET3_START + host_index_in_zone - 1

    if o2 > 254:
        raise ValueError("Too many external zones. Ran out of 172.x.x.x ranges.")

    if o3 > HOST_OCTET3_END:
        raise ValueError(
            f"Too many hosts in external zone Z{zone_index:04d}. "
            f"Current range supports {HOST_OCTET3_END - HOST_OCTET3_START + 1} hosts per zone."
        )

    simulated_ip = f"172.{o2}.{o3}.{o3}"
    gateway_ip = f"172.{o2}.{o3}.{GW_HOST_OCTET4}"

    return simulated_ip, gateway_ip


def external_group_key(ip):
    parts = ip.split(".")
    return ".".join(parts[:2])   # example: 172.31.11.11 -> 172.31


def assign_external_hosts(external_hosts):
    assigned = []
    zone_labels = []

    groups = defaultdict(list)

    for host in external_hosts:
        key = external_group_key(host["original_ip"])
        groups[key].append(host)

    external_host_index = 1
    zone_index = 2

    for group_key in sorted(groups.keys()):
        zone = zone_label(zone_index)
        zone_labels.append(zone)

        for host_pos, host in enumerate(
            sorted(groups[group_key], key=lambda x: x["original_ip"]),
            start=1,
        ):
            simulated_ip, gateway_ip = build_external_host_ips(zone_index, host_pos)

            assigned.append({
                **host,
                "zone": zone,
                "zone_index": zone_index,
                "service_name": f"{zone}_external_host_{host_pos:02d}",
                "simulated_ip": simulated_ip,
                "gateway_ip": gateway_ip,
                "external_group": group_key,
            })

          

        zone_index += 1

    return assigned, zone_labels


def build_simulated_topology(host_rows, edge_rows, dns_names, dhcp_zero_owner):
    grouped = {
        "internal": [],
        "external": [],
        "gateway": [],
        "dhcp_zero": [],
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

    for i, host in enumerate(
        sorted(grouped["internal"], key=lambda x: x["original_ip"]),
        start=1,
    ):
        simulated_ip, gateway_ip = build_internal_host_ips(i)

        mapping.append({
            **host,
            "zone": INTERNAL_ZONE,
            "zone_index": 1,
            "service_name": f"A_internal_host_{i:02d}",
            "simulated_ip": simulated_ip,
            "gateway_ip": gateway_ip,
        })

    internal_count = len(grouped["internal"])

    external_assigned, external_zone_labels = assign_external_hosts(grouped["external"])
    mapping.extend(external_assigned)

    # Special DHCP source mapping.
    #
    # We do NOT rewrite 0.0.0.0 to 172.x.x.x.
    # We only attach it to the real DHCP client container, so the replay script
    # knows which container should emit DHCP Discover/Request packets.
    owner_row = None

    if dhcp_zero_owner:
        for m in mapping:
            if m.get("original_ip") == dhcp_zero_owner:
                owner_row = m
                break

    if grouped["dhcp_zero"]:
        if owner_row:
            mapping.append({
                "original_ip": "0.0.0.0",
                "original_role": "dhcp_zero",
                "sim_type": "dhcp_zero",
                "zone": owner_row["zone"],
                "zone_index": owner_row["zone_index"],
                "service_name": owner_row["service_name"],
                "simulated_ip": "0.0.0.0",
                "gateway_ip": owner_row["gateway_ip"],
                "dhcp_assigned_original_ip": dhcp_zero_owner,
                "dhcp_assigned_simulated_ip": owner_row["simulated_ip"],
            })

            print(f"dhcp_zero=0.0.0.0 -> container={owner_row['service_name']} owner={dhcp_zero_owner}")
        else:
            grouped["ignore"].extend(grouped["dhcp_zero"])
            print("dhcp_zero=0.0.0.0 ignored because DHCP owner could not be detected")

    service_by_ip = {
        m["original_ip"]: m["service_name"]
        for m in mapping
        if m.get("original_ip")
    }

    sim_ip_by_ip = {
        m["original_ip"]: m["simulated_ip"]
        for m in mapping
        if m.get("original_ip")
    }

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

    zone_labels = [INTERNAL_ZONE] + external_zone_labels

    external_hosts_per_zone = []

    for zone in external_zone_labels:
        count = sum(
            1 for m in external_assigned
            if m["zone"] == zone
        )
        external_hosts_per_zone.append(count)

    hosts_per_zone = [internal_count] + external_hosts_per_zone

    simulated_topology = {
        "pcap_file": PCAP,
        "zones": len(zone_labels),
        "zone_labels": zone_labels,
        "hosts_per_zone": hosts_per_zone,
        "mapping": mapping,
        "ignored_hosts": grouped["ignore"],
        "edges": filtered_edges,
        "dns_names": dns_names,
        "dhcp_zero_owner": dhcp_zero_owner,
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
    dns_names = extract_dns_names()
    dhcp_zero_owner = extract_dhcp_zero_owner()

    host_rows = [
        {"ip": ip, "role": infer_role(ip)}
        for ip in sorted(hosts)
    ]

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
        "dns_names": dns_names,
        "dhcp_zero_owner": dhcp_zero_owner,
    }

    with open("topology.json", "w") as f:
        json.dump(topology, f, indent=2)

    print("Wrote topology.json")

    if dhcp_zero_owner:
        print(f"Detected DHCP 0.0.0.0 owner: {dhcp_zero_owner}")
    else:
        print("Detected DHCP 0.0.0.0 owner: none")

    build_simulated_topology(host_rows, edge_rows, dns_names, dhcp_zero_owner)


if __name__ == "__main__":
    main()