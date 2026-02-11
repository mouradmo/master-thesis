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
. Zone C
.  
.

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
ZONE_C_OCTET2 = 32
ZONE_D_OCTET2 = 33

A_SERVER_OCTET3 = 10
A_INTERNAL_OCTET3_START = 11  # internal_host_01 -> 11, internal_host_02 -> 12, ...

B_EXTERNAL_OCTET3_START = 11  # external_host_01 -> 11, external_host_02 -> 12, ...
C_EXTERNAL_OCTET3_START = 11
D_EXTERNAL_OCTET3_START = 11

GW_HOST_OCTET4 = 254


def net_name_a_server() -> str:
    return "A_server_net"


def net_name_a_internal(i: int) -> str:
    return f"A_internal_host_{i:02d}_net"


def net_name_b_external(i: int) -> str:
    return f"B_external_host_{i:02d}_net"


def net_name_c_external(i: int) -> str:
    return f"C_external_host_{i:02d}_net"


def net_name_d_external(i: int) -> str:
    return f"D_external_host_{i:02d}_net"


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
    num_a_internal_hosts: int,
    num_b_external_hosts: int,
    num_c_external_hosts: int,
    num_d_external_hosts: int,
    a_internal_octet3_start: int,
    b_external_octet3_start: int,
    c_external_octet3_start: int,
    d_external_octet3_start: int,
    pcap_filename: str,

) -> Dict[str, Any]:

    validate_octet3_range(a_internal_octet3_start, num_a_internal_hosts, "A-zone internal hosts")
    validate_octet3_range(b_external_octet3_start, num_b_external_hosts, "B-zone external hosts")
    validate_octet3_range(c_external_octet3_start, num_c_external_hosts, "C-zone external hosts")
    validate_octet3_range(d_external_octet3_start, num_d_external_hosts, "D-zone external hosts")

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

    # --- Networks: Zone A internal hosts (one /24 per host)
    a_internal_octets: List[int] = []
    for i in range(1, num_a_internal_hosts + 1):
        octet3 = a_internal_octet3_start + (i - 1)
        a_internal_octets.append(octet3)
        networks[net_name_a_internal(i)] = {
            "driver": "bridge",
            "ipam": {"config": [{"subnet": subnet(ZONE_A_OCTET2, octet3)}]},
        }

    # --- Networks: Zone B external hosts (one /24 per host)
    b_external_octets: List[int] = []
    for i in range(1, num_b_external_hosts + 1):
        octet3 = b_external_octet3_start + (i - 1)
        b_external_octets.append(octet3)
        networks[net_name_b_external(i)] = {
            "driver": "bridge",
            "ipam": {"config": [{"subnet": subnet(ZONE_B_OCTET2, octet3)}]},
        }
    # --- Networks: Zone C external hosts (one /24 per host)
    c_external_octets: List[int] = []
    for i in range(1, num_c_external_hosts + 1):
        octet3 = c_external_octet3_start + (i - 1)
        c_external_octets.append(octet3)
        networks[net_name_c_external(i)] = {
            "driver": "bridge",
            "ipam": {"config": [{"subnet": subnet(ZONE_C_OCTET2, octet3)}]},
        }
    # --- Networks: Zone D external hosts (one /24 per host)
        d_external_octets: List[int] = []
    for i in range(1, num_d_external_hosts + 1):
        octet3 = d_external_octet3_start + (i - 1)
        d_external_octets.append(octet3)
        networks[net_name_d_external(i)] = {
            "driver": "bridge",
            "ipam": {"config": [{"subnet": subnet(ZONE_D_OCTET2, octet3)}]},
        }
    # --- Gateway (connects to all subnets)
    gw_networks: Dict[str, Any] = {
        net_name_a_server(): {"ipv4_address": gw_ip(ZONE_A_OCTET2, A_SERVER_OCTET3)}
    }

    for i, octet3 in enumerate(a_internal_octets, start=1):
        gw_networks[net_name_a_internal(i)] = {"ipv4_address": gw_ip(ZONE_A_OCTET2, octet3)}

    for i, octet3 in enumerate(b_external_octets, start=1):
        gw_networks[net_name_b_external(i)] = {"ipv4_address": gw_ip(ZONE_B_OCTET2, octet3)}

    for i, octet3 in enumerate(c_external_octets, start=1):
        gw_networks[net_name_c_external(i)] = {"ipv4_address": gw_ip(ZONE_C_OCTET2, octet3)}

    for i, octet3 in enumerate(d_external_octets, start=1):
        gw_networks[net_name_d_external(i)] = {"ipv4_address": gw_ip(ZONE_D_OCTET2, octet3)}

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

    # --- Zone A internal hosts
    for i, octet3 in enumerate(a_internal_octets, start=1):
        name = f"A_internal_host_{i:02d}"
        net = net_name_a_internal(i)
        ip_addr = host_ip_pattern(ZONE_A_OCTET2, octet3)
        gw_addr = gw_ip(ZONE_A_OCTET2, octet3)

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

    # --- Helper for external zones (B/C/D)
    def add_external_zone(
        zone_letter: str,
        octet2: int,
        host_octets: List[int],
        net_name_fn,
    ) -> None:
        for i, octet3 in enumerate(host_octets, start=1):
            name = f"{zone_letter}_external_host_{i:02d}"
            net = net_name_fn(i)
            ip_addr = host_ip_pattern(octet2, octet3)
            gw_addr = gw_ip(octet2, octet3)

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

    add_external_zone("B", ZONE_B_OCTET2, b_external_octets, net_name_b_external)
    add_external_zone("C", ZONE_C_OCTET2, c_external_octets, net_name_c_external)
    add_external_zone("D", ZONE_D_OCTET2, d_external_octets, net_name_d_external)

    # --- Capture at gateway: include all subnets
    all_subnets: List[str] = [
        subnet(ZONE_A_OCTET2, A_SERVER_OCTET3),
        *[subnet(ZONE_A_OCTET2, o3) for o3 in a_internal_octets],
        *[subnet(ZONE_B_OCTET2, o3) for o3 in b_external_octets],
        *[subnet(ZONE_C_OCTET2, o3) for o3 in c_external_octets],
        *[subnet(ZONE_D_OCTET2, o3) for o3 in d_external_octets],
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

    ap.add_argument("--a-internal-hosts", type=int, default=1, help="Zone-A internal hosts (one /24 per host)")

    ap.add_argument("--b-external-hosts", type=int, default=1, help="Zone-B external hosts (one /24 per host)")
    ap.add_argument("--c-external-hosts", type=int, default=0, help="Zone-C external hosts (one /24 per host)")
    ap.add_argument("--d-external-hosts", type=int, default=0, help="Zone-D external hosts (one /24 per host)")

    ap.add_argument("--a-internal-octet3-start", type=int, default=A_INTERNAL_OCTET3_START)
    ap.add_argument("--b-external-octet3-start", type=int, default=B_EXTERNAL_OCTET3_START)
    ap.add_argument("--c-external-octet3-start", type=int, default=C_EXTERNAL_OCTET3_START)
    ap.add_argument("--d-external-octet3-start", type=int, default=D_EXTERNAL_OCTET3_START)

    ap.add_argument("--pcap", default="gateway.pcap")
    ap.add_argument("--out", default="docker-compose.yml")
    args = ap.parse_args()

    compose = make_compose(
        num_a_internal_hosts=args.a_internal_hosts,
        num_b_external_hosts=args.b_external_hosts,
        num_c_external_hosts=args.c_external_hosts,
        num_d_external_hosts=args.d_external_hosts,
        a_internal_octet3_start=args.a_internal_octet3_start,
        b_external_octet3_start=args.b_external_octet3_start,
        c_external_octet3_start=args.c_external_octet3_start,
        d_external_octet3_start=args.d_external_octet3_start,
        pcap_filename=args.pcap,
    )

    Path(args.out).write_text(
        yaml.safe_dump(compose, sort_keys=False, indent=2, width=120),
        encoding="utf-8",
    )
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()