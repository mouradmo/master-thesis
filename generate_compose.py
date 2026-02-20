#!/usr/bin/env python3
from __future__ import annotations

import argparse
import string
from pathlib import Path
from typing import Any, Dict, List

import yaml

GW_HOST_OCTET4 = 254

A_OCTET2_BASE = 30
A_SERVER_OCTET3 = 10
HOST_OCTET3_START = 11  # host_01 -> 11 (=> .11.11), host_02 -> 12, ...


def zone_letters(n: int) -> List[str]:
    if n < 1:
        raise ValueError("zones must be >= 1 (Zone A must exist)")
    if n > 26:
        raise ValueError("supports up to 26 zones (A-Z)")
    return list(string.ascii_uppercase[:n])


def parse_hosts_per_zone(s: str, zones: int) -> List[int]:
    parts = [p.strip() for p in s.split(",") if p.strip() != ""]
    if len(parts) != zones:
        raise ValueError(f"--hosts-per-zone must have exactly {zones} integers (for zones A..)")
    counts = [int(p) for p in parts]
    if any(c < 0 for c in counts):
        raise ValueError("host counts must be >= 0")
    if any(c > 200 for c in counts):
        raise ValueError("host counts must be <= 200")
    # also ensure we won't exceed octet3 253
    for zi, c in enumerate(counts):
        if c == 0:
            continue
        end = HOST_OCTET3_START + c - 1
        if end > 253:
            z = string.ascii_uppercase[zi]
            raise ValueError(f"Zone {z}: host octet3 range exceeds .253 (start={HOST_OCTET3_START}, count={c})")
    return counts


def subnet(o2: int, o3: int) -> str:
    return f"172.{o2}.{o3}.0/24"


def gw_ip(o2: int, o3: int) -> str:
    return f"172.{o2}.{o3}.{GW_HOST_OCTET4}"


def host_ip_pattern(o2: int, o3: int) -> str:
    # matches: 172.<o2>.<o3>.<o3>
    return f"172.{o2}.{o3}.{o3}"


def net_name_a_server() -> str:
    return "A_server_net"


def net_name_a_internal(i: int) -> str:
    return f"A_internal_host_{i:02d}_net"


def net_name_external(zone: str, i: int) -> str:
    return f"{zone}_external_host_{i:02d}_net"


def make_compose(num_zones: int, hosts_per_zone: List[int], pcap_filename: str) -> Dict[str, Any]:
    zones = zone_letters(num_zones)

    compose: Dict[str, Any] = {"networks": {}, "services": {}}
    networks: Dict[str, Any] = compose["networks"]
    services: Dict[str, Any] = compose["services"]

    # --- Build networks + gw attachments
    gw_networks: Dict[str, Any] = {}

    all_subnets: List[str] = []

    for zi, z in enumerate(zones):
        o2 = A_OCTET2_BASE + zi
        host_count = hosts_per_zone[zi]

        if z == "A":
            # Server subnet (only in A)
            networks[net_name_a_server()] = {
                "driver": "bridge",
                "ipam": {"config": [{"subnet": subnet(o2, A_SERVER_OCTET3)}]},
            }
            gw_networks[net_name_a_server()] = {"ipv4_address": gw_ip(o2, A_SERVER_OCTET3)}
            all_subnets.append(subnet(o2, A_SERVER_OCTET3))

            # Internal hosts: start at 11 (=> .11.11)
            for i in range(1, host_count + 1):
                o3 = HOST_OCTET3_START + (i - 1)
                net = net_name_a_internal(i)
                networks[net] = {
                    "driver": "bridge",
                    "ipam": {"config": [{"subnet": subnet(o2, o3)}]},
                }
                gw_networks[net] = {"ipv4_address": gw_ip(o2, o3)}
                all_subnets.append(subnet(o2, o3))

        else:
            # External zones: NO server subnet, hosts start at 11 (=> .11.11)
            for i in range(1, host_count + 1):
                o3 = HOST_OCTET3_START + (i - 1)
                net = net_name_external(z, i)
                networks[net] = {
                    "driver": "bridge",
                    "ipam": {"config": [{"subnet": subnet(o2, o3)}]},
                }
                gw_networks[net] = {"ipv4_address": gw_ip(o2, o3)}
                all_subnets.append(subnet(o2, o3))

    # --- Gateway
    services["gw"] = {
        "image": "nicolaka/netshoot:latest",
        "container_name": "master-thesis-gw",
        "cap_add": ["NET_ADMIN", "NET_RAW"],
        "sysctls": {"net.ipv4.ip_forward": "1"},
        "networks": gw_networks,
        "command": (
            "sh -c \""
            "iptables -F; iptables -t nat -F; iptables -t mangle -F; "
            "iptables -P INPUT ACCEPT; iptables -P OUTPUT ACCEPT; iptables -P FORWARD ACCEPT; "
            "echo 'GW ready'; "
            "sleep infinity"
            "\""
        ),
    }

    # --- Server (only in Zone A)
    a_o2 = A_OCTET2_BASE
    server_ip = f"172.{a_o2}.{A_SERVER_OCTET3}.{A_SERVER_OCTET3}"  # 172.30.10.10
    server_gw = gw_ip(a_o2, A_SERVER_OCTET3)

    services["server"] = {
        "image": "nginx:latest",
        "container_name": "master-thesis-server",
        "networks": {net_name_a_server(): {"ipv4_address": server_ip}},
    }

    services["server_route"] = {
        "image": "nicolaka/netshoot:latest",
        "container_name": "master-thesis-server-route",
        "network_mode": "service:server",
        "depends_on": ["server", "gw"],
        "cap_add": ["NET_ADMIN"],
        "command": (
            "sh -c \""
            "ip route del default 2>/dev/null || true; "
            f"ip route add default via {server_gw}; "
            "sleep infinity"
            "\""
        ),
    }

    # --- Hosts (A internal + external zones)
    for zi, z in enumerate(zones):
        o2 = A_OCTET2_BASE + zi
        host_count = hosts_per_zone[zi]

        if z == "A":
            # internal hosts in A
            for i in range(1, host_count + 1):
                o3 = HOST_OCTET3_START + (i - 1)
                name = f"A_internal_host_{i:02d}"
                net = net_name_a_internal(i)
                ip_addr = host_ip_pattern(o2, o3)
                gw_addr = gw_ip(o2, o3)

                services[name] = {
                    "image": "curlimages/curl:latest",
                    "container_name": f"master-thesis-{name}",
                    "command": "sleep infinity",
                    "networks": {net: {"ipv4_address": ip_addr}},
                }

                services[f"{name}_route"] = {
                    "image": "nicolaka/netshoot:latest",
                    "container_name": f"master-thesis-{name}-route",
                    "network_mode": f"service:{name}",
                    "depends_on": [name, "gw"],
                    "cap_add": ["NET_ADMIN"],
                    "command": (
                        "sh -c \""
                        "ip route del default 2>/dev/null || true; "
                        f"ip route add default via {gw_addr}; "
                        "sleep infinity"
                        "\""
                    ),
                }
        else:
            # external hosts in zone z
            for i in range(1, host_count + 1):
                o3 = HOST_OCTET3_START + (i - 1)
                name = f"{z}_external_host_{i:02d}"
                net = net_name_external(z, i)
                ip_addr = host_ip_pattern(o2, o3)
                gw_addr = gw_ip(o2, o3)

                services[name] = {
                    "image": "nicolaka/netshoot:latest",
                    "container_name": f"master-thesis-{name}",
                    "cap_add": ["NET_ADMIN", "NET_RAW"],
                    "networks": {net: {"ipv4_address": ip_addr}},
                    "command": "sleep infinity",
                }

                services[f"{name}_route"] = {
                    "image": "nicolaka/netshoot:latest",
                    "container_name": f"master-thesis-{name}-route",
                    "network_mode": f"service:{name}",
                    "depends_on": [name, "gw"],
                    "cap_add": ["NET_ADMIN"],
                    "command": (
                        "sh -c \""
                        "ip route del default 2>/dev/null || true; "
                        f"ip route add default via {gw_addr}; "
                        "sleep infinity"
                        "\""
                    ),
                }

    # --- Capture at gateway (all subnets)
    net_filter = " or ".join([f"net {s}" for s in all_subnets]) if all_subnets else "ip"

    services["capture"] = {
        "image": "nicolaka/netshoot:latest",
        "container_name": "master-thesis-capture",
        "network_mode": "service:gw",
        "depends_on": ["gw"],
        "cap_add": ["NET_ADMIN", "NET_RAW"],
        "volumes": ["./:/data"],
        "command": (
            "sh -c \""
            f"tcpdump -U -i any -nn -s 0 '({net_filter}) and not arp' "
            f"-w /data/{pcap_filename}"
            "\""
        ),
    }

    return compose


def main() -> None:
    ap = argparse.ArgumentParser()

    ap.add_argument("--zones", type=int, required=True, help="Number of zones (includes A). Example: 4 => A,B,C,D")
    ap.add_argument(
        "--hosts-per-zone",
        type=str,
        required=True,
        help="Comma-separated host counts for zones A,B,C,... Example: 2,3,1,0",
    )

    ap.add_argument("--pcap", default="gateway.pcap")
    ap.add_argument("--out", default="docker-compose.yml")
    args = ap.parse_args()

    hosts_per_zone = parse_hosts_per_zone(args.hosts_per_zone, args.zones)
    compose = make_compose(num_zones=args.zones, hosts_per_zone=hosts_per_zone, pcap_filename=args.pcap)

    Path(args.out).write_text(
        yaml.safe_dump(compose, sort_keys=False, indent=2, width=120),
        encoding="utf-8",
    )
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
