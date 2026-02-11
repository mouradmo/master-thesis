#!/usr/bin/env python3
"""
- Zone A (internal) uses 172.30.<X>.0/24
    - Server lives alone in 172.30.10.0/24
    - Each A-zone client gets its OWN /24:
        client_1 -> 172.30.11.0/24 (host IP 172.30.11.11)
        client_2 -> 172.30.12.0/24 (host IP 172.30.12.12)
        ... MAX 200 clients 
- Zone B (outside) uses 172.31.<X>.0/24
    - Each B-zone host gets its OWN /24:
        host_1 -> 172.31.11.0/24 (host IP 172.31.11.11)
        host_2 -> 172.31.12.0/24 (host IP 172.31.12.12)
        ... MAX 200 hosts
- Single gateway (gw) attaches to ALL subnets and routes between them (no NAT)
- Capture runs at the gateway and includes ALL subnets
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

import yaml

ZONE_A_OCTET2 = 30
ZONE_B_OCTET2 = 31

A_SERVER_OCTET3 = 10
A_CLIENTS_OCTET3_START = 11  # client_1 -> 11, client_2 -> 12, ...

B_HOSTS_OCTET3_START = 11    # host_1 -> 11, host_2 -> 12, ...

GW_HOST_OCTET4 = 254


def net_name_a_server() -> str:
    return "A_zone_server_net"


def net_name_a_client(i: int) -> str:
    return f"A_zone_client_{i}_net"


def net_name_b_host(i: int) -> str:
    return f"B_zone_host_{i}_net"


def subnet(octet2: int, octet3: int) -> str:
    return f"172.{octet2}.{octet3}.0/24"


def gw_ip(octet2: int, octet3: int) -> str:
    return f"172.{octet2}.{octet3}.{GW_HOST_OCTET4}"


def host_ip_pattern(octet2: int, octet3: int) -> str:
    """
    172.30.11.11, 172.30.12.12, 172.31.11.11, ...
    """
    return f"172.{octet2}.{octet3}.{octet3}"


def validate_octet3_range(start: int, count: int, label: str) -> None:
    if count < 0 or count > 200:
        raise ValueError(f"{label} count must be between 0 and 200")
    end = start + count - 1
    if count > 0 and end > 253:
        raise ValueError(f"{label} octet3 range exceeds .253 (start={start}, count={count})")


def make_compose(
    num_a_clients: int,
    num_b_hosts: int,
    a_clients_octet3_start: int,
    b_hosts_octet3_start: int,
    pcap_filename: str,
) -> Dict[str, Any]:

    validate_octet3_range(a_clients_octet3_start, num_a_clients, "A-zone clients")
    validate_octet3_range(b_hosts_octet3_start, num_b_hosts, "B-zone hosts")

    compose: Dict[str, Any] = {
        "networks": {},
        "services": {},
    }

    networks = compose["networks"]
    services = compose["services"]

    # --- Networks: Zone A server subnet
    networks[net_name_a_server()] = {
        "driver": "bridge",
        "ipam": {"config": [{"subnet": subnet(ZONE_A_OCTET2, A_SERVER_OCTET3)}]},
    }

    # --- Networks: Zone A clients (one /24 per client)
    a_client_octets: List[int] = []
    for i in range(1, num_a_clients + 1):
        octet3 = a_clients_octet3_start + (i - 1)
        a_client_octets.append(octet3)
        networks[net_name_a_client(i)] = {
            "driver": "bridge",
            "ipam": {"config": [{"subnet": subnet(ZONE_A_OCTET2, octet3)}]},
        }

    # --- Networks: Zone B hosts (one /24 per host)
    b_host_octets: List[int] = []
    for i in range(1, num_b_hosts + 1):
        octet3 = b_hosts_octet3_start + (i - 1)
        b_host_octets.append(octet3)
        networks[net_name_b_host(i)] = {
            "driver": "bridge",
            "ipam": {"config": [{"subnet": subnet(ZONE_B_OCTET2, octet3)}]},
        }

    # --- Gateway (connects to all subnets)
    gw_networks: Dict[str, Any] = {
        net_name_a_server(): {"ipv4_address": gw_ip(ZONE_A_OCTET2, A_SERVER_OCTET3)}
    }

    for i, octet3 in enumerate(a_client_octets, start=1):
        gw_networks[net_name_a_client(i)] = {"ipv4_address": gw_ip(ZONE_A_OCTET2, octet3)}

    for i, octet3 in enumerate(b_host_octets, start=1):
        gw_networks[net_name_b_host(i)] = {"ipv4_address": gw_ip(ZONE_B_OCTET2, octet3)}

    services["gw"] = {
        "image": "nicolaka/netshoot:latest",
        "container_name": "master-thesis-gw",
        "cap_add": ["NET_ADMIN", "NET_RAW"],
        "sysctls": {"net.ipv4.ip_forward": "1"},
        "networks": gw_networks,
        "command": (
            "sh -c \""
            "iptables -F && iptables -t nat -F; "
            "iptables -P FORWARD ACCEPT; "
            "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; "
            "echo 'GW ready'; "
            "sleep infinity"
            "\""
        ),
    }

    # --- Server (alone in 172.30.10.0/24)
    server_ip = "172.30.10.10"
    server_gw = gw_ip(ZONE_A_OCTET2, A_SERVER_OCTET3)

    services["server"] = {
        "image": "nginx:latest",
        "container_name": "master-thesis-server",
        "networks": {net_name_a_server(): {"ipv4_address": server_ip}},
    }

    # Force server default route via gw leg on its subnet
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

    # --- Zone A clients, one client per /24
    for i, octet3 in enumerate(a_client_octets, start=1):
        client_name = f"A_zone_client_{i}"
        client_net = net_name_a_client(i)
        client_ip = host_ip_pattern(ZONE_A_OCTET2, octet3)
        client_gw = gw_ip(ZONE_A_OCTET2, octet3)

        services[client_name] = {
            "image": "curlimages/curl:latest",
            "container_name": f"master-thesis-{client_name}",
            "command": "sleep infinity",
            "networks": {client_net: {"ipv4_address": client_ip}},
        }

        services[f"{client_name}_route"] = {
            "image": "nicolaka/netshoot:latest",
            "container_name": f"master-thesis-{client_name}-route",
            "network_mode": f"service:{client_name}",
            "depends_on": [client_name, "gw"],
            "cap_add": ["NET_ADMIN"],
            "command": (
                "sh -c \""
                "ip route del default 2>/dev/null || true; "
                f"ip route add default via {client_gw}; "
                "sleep infinity"
                "\""
            ),
        }

    # --- Zone B hosts, one host per /24
    for i, octet3 in enumerate(b_host_octets, start=1):
        host_name = f"B_zone_host_{i}"
        host_net = net_name_b_host(i)
        host_ip = host_ip_pattern(ZONE_B_OCTET2, octet3)
        host_gw = gw_ip(ZONE_B_OCTET2, octet3)

        services[host_name] = {
            "image": "nicolaka/netshoot:latest",
            "container_name": f"master-thesis-{host_name}",
            "cap_add": ["NET_ADMIN", "NET_RAW"],
            "networks": {host_net: {"ipv4_address": host_ip}},
            "command": "sleep infinity",
        }

        services[f"{host_name}_route"] = {
            "image": "nicolaka/netshoot:latest",
            "container_name": f"master-thesis-{host_name}-route",
            "network_mode": f"service:{host_name}",
            "depends_on": [host_name, "gw"],
            "cap_add": ["NET_ADMIN"],
            "command": (
                "sh -c \""
                "ip route del default 2>/dev/null || true; "
                f"ip route add default via {host_gw}; "
                "sleep infinity"
                "\""
            ),
        }

    # --- Capture at gateway: include all subnets
    all_subnets: List[str] = [
        subnet(ZONE_A_OCTET2, A_SERVER_OCTET3),
        *[subnet(ZONE_A_OCTET2, o3) for o3 in a_client_octets],
        *[subnet(ZONE_B_OCTET2, o3) for o3 in b_host_octets],
    ]

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
    ap.add_argument("--a-clients", type=int, default=1, help="Number of Zone-A clients (one /24 per client)")
    ap.add_argument("--b-hosts", type=int, default=1, help="Number of Zone-B hosts (one /24 per host)")
    ap.add_argument("--a-clients-octet3-start", type=int, default=A_CLIENTS_OCTET3_START)
    ap.add_argument("--b-hosts-octet3-start", type=int, default=B_HOSTS_OCTET3_START)
    ap.add_argument("--pcap", default="gateway.pcap")
    ap.add_argument("--out", default="docker-compose.yml")
    args = ap.parse_args()

    compose = make_compose(
        num_a_clients=args.a_clients,
        num_b_hosts=args.b_hosts,
        a_clients_octet3_start=args.a_clients_octet3_start,
        b_hosts_octet3_start=args.b_hosts_octet3_start,
        pcap_filename=args.pcap,
    )

    Path(args.out).write_text(
        yaml.safe_dump(compose, sort_keys=False, indent=2, width=120),
        encoding="utf-8",
    )
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
