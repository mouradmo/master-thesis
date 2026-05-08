#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import yaml


EXTERNAL_IMAGE_NAME = "nicolaka/netshoot:latest"
ROUTE_IMAGE = "nicolaka/netshoot:latest"
INTERNAL_IMAGE = "curlimages/curl:latest"

DOCKER_PREFIX = "master-thesis-"


def subnet_from_gateway(gateway_ip: str) -> str:
    parts = gateway_ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"Invalid gateway IP: {gateway_ip}")

    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def net_name_from_service(service_name: str) -> str:
    return f"{service_name}_net"


def add_network(
    networks: Dict[str, Any],
    gw_networks: Dict[str, Any],
    all_subnets: List[str],
    net: str,
    gateway_ip: str,
) -> None:
    subnet = subnet_from_gateway(gateway_ip)

    if net in networks:
        return

    networks[net] = {
        "driver": "bridge",
        "ipam": {
            "config": [
                {
                    "subnet": subnet,
                }
            ]
        },
    }

    gw_networks[net] = {"ipv4_address": gateway_ip}

    if subnet not in all_subnets:
        all_subnets.append(subnet)


def make_host_services(
    name: str,
    net: str,
    ip_addr: str,
    gw_addr: str,
    image: str,
    extra_caps: List[str] | None = None,
) -> Dict[str, Any]:
    main: Dict[str, Any] = {
        "image": image,
        "container_name": f"{DOCKER_PREFIX}{name}",
        "command": "sleep infinity",
        "networks": {
            net: {
                "ipv4_address": ip_addr,
            }
        },
    }

    if extra_caps:
        main["cap_add"] = extra_caps

    route: Dict[str, Any] = {
        "image": ROUTE_IMAGE,
        "container_name": f"{DOCKER_PREFIX}{name}-route",
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

    return {
        name: main,
        f"{name}_route": route,
    }


def load_topology(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_active_mappings(topo: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Return only rows that should become real Docker containers.

    Important:
    - gateway is created separately as service "gw"
    - ignore rows are not simulated
    - dhcp_zero is metadata only; it uses 0.0.0.0 and must NOT become
      a Docker container/network
    """

    rows: List[Dict[str, Any]] = []
    seen_services = set()

    for row in topo.get("mapping", []):
        sim_type = row.get("sim_type", "")

        if sim_type in {"ignore", "gateway", "dhcp_zero"}:
            continue

        service_name = row.get("service_name", "")
        simulated_ip = row.get("simulated_ip", "")
        gateway_ip = row.get("gateway_ip", "")

        if not service_name:
            continue
        if not simulated_ip:
            continue
        if not gateway_ip:
            continue

        if simulated_ip == "0.0.0.0":
            continue

        if service_name in seen_services:
            continue

        seen_services.add(service_name)
        rows.append(row)

    return rows


def make_compose_from_topology(
    topo: Dict[str, Any],
    pcap_filename: str,
) -> Dict[str, Any]:
    compose: Dict[str, Any] = {
        "services": {},
        "networks": {},
    }

    services: Dict[str, Any] = compose["services"]
    networks: Dict[str, Any] = compose["networks"]

    gw_networks: Dict[str, Any] = {}
    all_subnets: List[str] = []

    active_hosts = get_active_mappings(topo)

    if not active_hosts:
        raise ValueError("No active host mappings found in topology.")

    for row in active_hosts:
        service_name = row["service_name"]
        gateway_ip = row["gateway_ip"]
        net = net_name_from_service(service_name)

        add_network(
            networks=networks,
            gw_networks=gw_networks,
            all_subnets=all_subnets,
            net=net,
            gateway_ip=gateway_ip,
        )

    services["gw"] = {
        "image": ROUTE_IMAGE,
        "container_name": f"{DOCKER_PREFIX}gw",
        "cap_add": ["NET_ADMIN", "NET_RAW"],
        "sysctls": {
            "net.ipv4.ip_forward": "1",
        },
        "networks": gw_networks,
        "command": (
            "sh -c \""
            "iptables -F; "
            "iptables -t nat -F; "
            "iptables -t mangle -F; "
            "iptables -P INPUT ACCEPT; "
            "iptables -P OUTPUT ACCEPT; "
            "iptables -P FORWARD ACCEPT; "
            "echo 'GW ready'; "
            "sleep infinity"
            "\""
        ),
    }

    for row in active_hosts:
        name = row["service_name"]
        net = net_name_from_service(name)
        ip_addr = row["simulated_ip"]
        gw_addr = row["gateway_ip"]
        sim_type = row.get("sim_type", "")

        if sim_type == "internal":
            image = INTERNAL_IMAGE
            extra_caps = ["NET_ADMIN", "NET_RAW"]
        else:
            image = EXTERNAL_IMAGE_NAME
            extra_caps = ["NET_ADMIN", "NET_RAW"]

        services.update(
            make_host_services(
                name=name,
                net=net,
                ip_addr=ip_addr,
                gw_addr=gw_addr,
                image=image,
                extra_caps=extra_caps,
            )
        )

    net_filter = " or ".join(f"net {s}" for s in all_subnets) if all_subnets else "ip"

    services["capture"] = {
        "image": ROUTE_IMAGE,
        "container_name": f"{DOCKER_PREFIX}capture",
        "profiles": ["capture"],
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
    ap.add_argument(
        "--topology",
        required=True,
        help="Path to simulated_topology.json",
    )
    ap.add_argument(
        "--pcap",
        default="gateway.pcap",
        help="Capture filename used by optional capture service",
    )
    ap.add_argument(
        "--out",
        default="docker-compose.yml",
        help="Output docker-compose YAML path",
    )

    args = ap.parse_args()

    topo = load_topology(args.topology)
    compose = make_compose_from_topology(topo, args.pcap)

    Path(args.out).write_text(
        yaml.safe_dump(
            compose,
            sort_keys=False,
            indent=2,
            width=120,
        ),
        encoding="utf-8",
    )

    active_hosts = get_active_mappings(topo)
    skipped_dhcp = sum(
        1 for row in topo.get("mapping", [])
        if row.get("sim_type") == "dhcp_zero"
    )

    print(f"Wrote {args.out}")
    print(f"services={len(compose['services'])}")
    print(f"networks={len(compose['networks'])}")
    print(f"active_hosts={len(active_hosts)}")
    print(f"skipped_dhcp_zero={skipped_dhcp}")


if __name__ == "__main__":
    main()