#!/usr/bin/env python3
"""
Generate docker-compose.yml for the master-thesis testbed.

Topology (segmented so GW sees client<->server traffic):

- a_server_net:  172.30.0.0/24   (server)
- b_client_net:  172.31.0.0/24   (clients)
- c_outside_net: 172.32.0.0/24   (attackers)
"""

from __future__ import annotations
import argparse
from pathlib import Path
from typing import Dict, Any
import yaml

SERVER_SUBNET = "172.30.0.0/24"
CLIENT_SUBNET = "172.31.0.0/24"
OUTSIDE_SUBNET = "172.32.0.0/24"

GW_SERVER_IP = "172.30.0.254"
GW_CLIENT_IP = "172.31.0.254"
GW_OUTSIDE_IP = "172.32.0.254"

SERVER_IP = "172.30.0.10"

# Network names (alphabetical prefixes)
SERVER_NET = "a_server_net"
CLIENT_NET = "b_client_net"
OUTSIDE_NET = "c_outside_net"


def make_compose(num_clients: int, num_attackers: int, pcap_filename: str) -> Dict[str, Any]:
    if not (0 <= num_clients <= 200):
        raise ValueError("num_clients must be between 0 and 200")
    if not (0 <= num_attackers <= 100):
        raise ValueError("num_attackers must be between 0 and 100")

    # Keep networks in a->b->c order (also helps readability)
    compose: Dict[str, Any] = {
        "networks": {
            SERVER_NET: {
                "driver": "bridge",
                "ipam": {"config": [{"subnet": SERVER_SUBNET}]},
            },
            CLIENT_NET: {
                "driver": "bridge",
                "ipam": {"config": [{"subnet": CLIENT_SUBNET}]},
            },
            OUTSIDE_NET: {
                "driver": "bridge",
                "ipam": {"config": [{"subnet": OUTSIDE_SUBNET}]},
            },
        },
        "services": {},
    }

    services = compose["services"]

    # Gateway (routing only; no NAT)
    services["gw"] = {
        "image": "nicolaka/netshoot:latest",
        "container_name": "master-thesis-gw",
        "cap_add": ["NET_ADMIN", "NET_RAW"],
        "sysctls": {"net.ipv4.ip_forward": "1"},
        "networks": {
            SERVER_NET: {"ipv4_address": GW_SERVER_IP},
            CLIENT_NET: {"ipv4_address": GW_CLIENT_IP},
            OUTSIDE_NET: {"ipv4_address": GW_OUTSIDE_IP},
        },
        "command": (
            "sh -c \""
            "iptables -F && iptables -t nat -F; "
            "iptables -P FORWARD ACCEPT; "
            "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; "
            "echo 'GW ready: routing enabled (no NAT)'; "
            "sleep infinity"
            "\""
        ),
    }

    # Server on a_server_net
    services["server"] = {
        "image": "nginx:latest",
        "container_name": "master-thesis-server",
        "networks": {SERVER_NET: {"ipv4_address": SERVER_IP}},
    }

    # Server route sidecar
    services["server_route"] = {
        "image": "nicolaka/netshoot:latest",
        "container_name": "master-thesis-server-route",
        "network_mode": "service:server",
        "depends_on": ["server", "gw"],
        "cap_add": ["NET_ADMIN"],
        "command": (
            "sh -c \""
            "ip route del default; "
            f"ip route add default via {GW_SERVER_IP}; "
            "echo '[server_route] default route set'; "
            "sleep infinity"
            "\""
        ),
    }

    # Capture at GW
    services["capture"] = {
        "image": "nicolaka/netshoot:latest",
        "container_name": "master-thesis-capture",
        "network_mode": "service:gw",
        "depends_on": ["gw"],
        "cap_add": ["NET_ADMIN", "NET_RAW"],
        "volumes": ["./:/data"],
        "command": (
            "sh -c \""
            "tcpdump -U -i any -nn -s 0 "
            f"'(net {CLIENT_SUBNET} or net {OUTSIDE_SUBNET} or net {SERVER_SUBNET}) and not arp' "
            f"-w /data/{pcap_filename}"
            "\""
        ),
    }

    # Clients
    for i in range(num_clients):
        idx = i + 1
        ip_last = 10 + idx
        client_name = f"client{idx}"
        client_ip = f"172.31.0.{ip_last}"

        services[client_name] = {
            "image": "curlimages/curl:latest",
            "container_name": f"master-thesis-{client_name}",
            "command": "sleep infinity",
            "networks": {CLIENT_NET: {"ipv4_address": client_ip}},
        }

        services[f"{client_name}_route"] = {
            "image": "nicolaka/netshoot:latest",
            "container_name": f"master-thesis-{client_name}-route",
            "network_mode": f"service:{client_name}",
            "depends_on": [client_name, "gw"],
            "cap_add": ["NET_ADMIN"],
            "command": (
                "sh -c \""
                "ip route del default; "
                f"ip route add default via {GW_CLIENT_IP}; "
                f"ip route add {SERVER_SUBNET} via {GW_CLIENT_IP} 2>/dev/null || true; "
                f"echo '[{client_name}_route] routes set'; "
                "sleep infinity"
                "\""
            ),
        }

    # Attackers
    for i in range(num_attackers):
        idx = i + 1
        attacker_name = f"attacker{idx}"
        attacker_ip = f"172.32.0.{99 + idx}"

        services[attacker_name] = {
            "image": "nicolaka/netshoot:latest",
            "container_name": f"master-thesis-{attacker_name}",
            "cap_add": ["NET_ADMIN", "NET_RAW"],
            "networks": {OUTSIDE_NET: {"ipv4_address": attacker_ip}},
            "command": (
                "sh -c \""
                f"ip route add {CLIENT_SUBNET} via {GW_OUTSIDE_IP}; "
                f"ip route add {SERVER_SUBNET} via {GW_OUTSIDE_IP}; "
                "sleep infinity"
                "\""
            ),
        }

    return compose


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=1)
    ap.add_argument("--attackers", type=int, default=1)
    ap.add_argument("--pcap", default="gateway.pcap")
    ap.add_argument("--out", default="docker-compose.yml")
    args = ap.parse_args()

    compose = make_compose(args.clients, args.attackers, args.pcap)

    out_path = Path(args.out)
    with out_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(
            compose,
            f,
            sort_keys=False,          # keep insertion order
            default_flow_style=False,
            indent=2,
            width=120,
        )

    print(f"Wrote {out_path} with clients={args.clients}, attackers={args.attackers}, pcap={args.pcap}")


if __name__ == "__main__":
    main()
