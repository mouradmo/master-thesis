#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import string
from pathlib import Path
from typing import Any, Dict, List

import yaml

GW_HOST_OCTET4 = 254
A_OCTET2_BASE = 30
A_SERVER_OCTET3 = 10
HOST_OCTET3_START = 11  # host_01 -> 11 (=> .11.11), host_02 -> 12, ...

# CORE_DNS_IP = "172.30.10.53"

# Linux image for external hosts
EXTERNAL_IMAGE_NAME = "nicolaka/netshoot:latest"
ROUTE_IMAGE = "nicolaka/netshoot:latest"
INTERNAL_IMAGE = "curlimages/curl:latest"


def zone_letters(n: int) -> List[str]:
    if not 1 <= n <= 26:
        raise ValueError("zones must be between 1 and 26 (Zone A..Z)")
    return list(string.ascii_uppercase[:n])


def parse_hosts_per_zone(s: str, zones: int) -> List[int]:
    counts = [int(p.strip()) for p in s.split(",") if p.strip()]
    if len(counts) != zones:
        raise ValueError(f"--hosts-per-zone must have exactly {zones} integers (for zones A..)")
    if any(c < 0 for c in counts):
        raise ValueError("host counts must be >= 0")
    if any(c > 200 for c in counts):
        raise ValueError("host counts must be <= 200")

    for zi, c in enumerate(counts):
        if c and HOST_OCTET3_START + c - 1 > 253:
            raise ValueError(
                f"Zone {string.ascii_uppercase[zi]}: host octet3 range exceeds .253 "
                f"(start={HOST_OCTET3_START}, count={c})"
            )
    return counts


def subnet(o2: int, o3: int) -> str:
    return f"172.{o2}.{o3}.0/24"


def gw_ip(o2: int, o3: int) -> str:
    return f"172.{o2}.{o3}.{GW_HOST_OCTET4}"


def host_ip_pattern(o2: int, o3: int) -> str:
    return f"172.{o2}.{o3}.{o3}"


def net_name_a_server() -> str:
    return "A_server_net"


def net_name_a_internal(i: int) -> str:
    return f"A_internal_host_{i:02d}_net"


def net_name_external(zone: str, i: int) -> str:
    return f"{zone}_external_host_{i:02d}_net"


# def load_emulated_dns_names(topo: Dict[str, Any]) -> List[str]:
#     names = topo.get("dns_names", [])
#     if not isinstance(names, list):
#         return []
#
#     cleaned: List[str] = []
#     seen = set()
#
#     for name in names:
#         if not isinstance(name, str):
#             continue
#
#         name = name.strip().lower().rstrip(".")
#         if not name:
#             continue
#
#         if name not in seen:
#             seen.add(name)
#             cleaned.append(name)
#
#     return cleaned


def host_entries(zones: List[str], hosts_per_zone: List[int]):
    for zi, z in enumerate(zones):
        o2 = A_OCTET2_BASE + zi
        for i in range(1, hosts_per_zone[zi] + 1):
            o3 = HOST_OCTET3_START + (i - 1)
            if z == "A":
                name = f"A_internal_host_{i:02d}"
                net = net_name_a_internal(i)
                image = INTERNAL_IMAGE
                cap_add = None
            else:
                name = f"{z}_external_host_{i:02d}"
                net = net_name_external(z, i)
                image = EXTERNAL_IMAGE_NAME
                cap_add = ["NET_ADMIN", "NET_RAW"]

            yield {
                "zone": z,
                "o2": o2,
                "o3": o3,
                "name": name,
                "net": net,
                "image": image,
                "cap_add": cap_add,
                "ip_addr": host_ip_pattern(o2, o3),
                "gw_addr": gw_ip(o2, o3),
            }


def build_networks(zones: List[str], hosts_per_zone: List[int]):
    networks = {}
    gw_networks = {}
    all_subnets = []

    for zi, z in enumerate(zones):
        o2 = A_OCTET2_BASE + zi

        if z == "A":
            networks[net_name_a_server()] = {
                "driver": "bridge",
                "ipam": {"config": [{"subnet": subnet(o2, A_SERVER_OCTET3)}]},
            }
            gw_networks[net_name_a_server()] = {"ipv4_address": gw_ip(o2, A_SERVER_OCTET3)}
            all_subnets.append(subnet(o2, A_SERVER_OCTET3))

        for entry in host_entries([z], [hosts_per_zone[zi]]):
            networks[entry["net"]] = {
                "driver": "bridge",
                "ipam": {"config": [{"subnet": subnet(entry["o2"], entry["o3"])}]},
            }
            gw_networks[entry["net"]] = {"ipv4_address": entry["gw_addr"]}
            all_subnets.append(subnet(entry["o2"], entry["o3"]))

    return networks, gw_networks, all_subnets


def make_host_service(entry):
    svc = {
        "image": entry["image"],
        "container_name": f"master-thesis-{entry['name']}",
        "command": "sleep infinity",
        # "dns": [CORE_DNS_IP],
        # "dns_search": ["local"],
        "networks": {entry["net"]: {"ipv4_address": entry["ip_addr"]}},
    }
    if entry["cap_add"]:
        svc["cap_add"] = entry["cap_add"]
    return svc


def make_route_service(name: str, gw_addr: str):
    return {
        "image": ROUTE_IMAGE,
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


def make_compose(
    num_zones: int,
    hosts_per_zone: List[int],
    pcap_filename: str,
) -> Dict[str, Any]:
    zones = zone_letters(num_zones)
    services: Dict[str, Any] = {}
    networks, gw_networks, all_subnets = build_networks(zones, hosts_per_zone)

    services["gw"] = {
        "image": ROUTE_IMAGE,
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

    a_o2 = A_OCTET2_BASE
    server_ip = f"172.{a_o2}.{A_SERVER_OCTET3}.{A_SERVER_OCTET3}"  # 172.30.10.10
    server_gw = gw_ip(a_o2, A_SERVER_OCTET3)

    # base_dns_names = [
    #     "server.local",
    #     "c2.local",
    #     "api.ipify.org",
    #     "ipify.org",
    #     "github.com",
    # ]
    #
    # all_dns_names: List[str] = []
    # seen_dns = set()
    #
    # for name in base_dns_names + (dns_names or []):
    #     name = name.strip().lower().rstrip(".")
    #     if not name:
    #         continue
    #     if name not in seen_dns:
    #         seen_dns.add(name)
    #         all_dns_names.append(name)
    #
    # host_lines = "".join(f"        {server_ip} {name}\n" for name in all_dns_names)
    #
    # corefile_content = (
    #     ".:53 {\n"
    #     "    hosts {\n"
    #     f"{host_lines}"
    #     "        fallthrough\n"
    #     "    }\n"
    #     "    log\n"
    #     "    errors\n"
    #     "}\n"
    # )
    # Path("Corefile").write_text(corefile_content, encoding="utf-8")

    # services["server"] = {
    #     "image": "nginx:alpine",
    #     "container_name": "master-thesis-server",
    #     "networks": {net_name_a_server(): {"ipv4_address": server_ip}},
    #     "command": (
    #         "sh -c \""
    #         "cat > /etc/nginx/conf.d/default.conf <<'EOF'\n"
    #         "server {\n"
    #         "  listen 80;\n"
    #         "  server_name server.local;\n"
    #         "\n"
    #         "  location = / {\n"
    #         "    default_type text/html;\n"
    #         "    return 200 '<html><body><h1>Internal test server</h1></body></html>\\\\n';\n"
    #         "  }\n"
    #         "\n"
    #         "  location = /health {\n"
    #         "    default_type text/plain;\n"
    #         "    return 200 'healthy\\\\n';\n"
    #         "  }\n"
    #         "\n"
    #         "  location = /index.html {\n"
    #         "    default_type text/html;\n"
    #         "    return 200 '<html><body><p>index page</p></body></html>\\\\n';\n"
    #         "  }\n"
    #         "}\n"
    #         "\n"
    #         "server {\n"
    #         "  listen 80;\n"
    #         "  server_name c2.local;\n"
    #         "\n"
    #         "  location = / {\n"
    #         "    default_type application/json;\n"
    #         "    return 200 '{\\\"status\\\":\\\"online\\\"}\\\\n';\n"
    #         "  }\n"
    #         "\n"
    #         "  location = /api/beacon {\n"
    #         "    default_type application/json;\n"
    #         "    return 200 '{\\\"cmd\\\":\\\"sleep\\\",\\\"seconds\\\":5}\\\\n';\n"
    #         "  }\n"
    #         "\n"
    #         "  location = /api/task {\n"
    #         "    default_type application/json;\n"
    #         "    return 200 '{\\\"task\\\":\\\"noop\\\"}\\\\n';\n"
    #         "  }\n"
    #         "}\n"
    #         "\n"
    #         "server {\n"
    #         "  listen 80;\n"
    #         "  server_name api.ipify.org ipify.org;\n"
    #         "\n"
    #         "  location = / {\n"
    #         "    default_type text/plain;\n"
    #         "    return 200 '203.0.113.10\\\\n';\n"
    #         "  }\n"
    #         "}\n"
    #         "\n"
    #         "server {\n"
    #         "  listen 80 default_server;\n"
    #         "  server_name _;\n"
    #         "\n"
    #         "  location = / {\n"
    #         "    default_type text/html;\n"
    #         "    return 200 '<html><body><h1>Generic web reply</h1></body></html>\\\\n';\n"
    #         "  }\n"
    #         "\n"
    #         "  location = /robots.txt {\n"
    #         "    default_type text/plain;\n"
    #         "    return 200 'User-agent: *\\\\nDisallow:\\\\n';\n"
    #         "  }\n"
    #         "}\n"
    #         "EOF\n"
    #         "nginx -g 'daemon off;'\n"
    #         "\""
    #     ),
    # }

    # services["server_route"] = {
    #     "image": "nicolaka/netshoot:latest",
    #     "container_name": "master-thesis-server-route",
    #     "network_mode": "service:server",
    #     "depends_on": ["server", "gw"],
    #     "cap_add": ["NET_ADMIN"],
    #     "command": (
    #         "sh -c \""
    #         "ip route del default 2>/dev/null || true; "
    #         f"ip route add default via {server_gw}; "
    #         "sleep infinity"
    #         "\""
    #     ),
    # }

    # services["dns"] = {
    #     "image": "coredns/coredns:latest",
    #     "container_name": "master-thesis-dns",
    #     "networks": {net_name_a_server(): {"ipv4_address": CORE_DNS_IP}},
    #     "volumes": ["./Corefile:/Corefile:ro"],
    #     "command": ["-conf", "/Corefile"],
    # }

    # services["dns_route"] = {
    #     "image": "nicolaka/netshoot:latest",
    #     "container_name": "master-thesis-dns-route",
    #     "network_mode": "service:dns",
    #     "depends_on": ["dns", "gw"],
    #     "cap_add": ["NET_ADMIN"],
    #     "command": (
    #         "sh -c \""
    #         "ip route del default 2>/dev/null || true; "
    #         "ip route add default via 172.30.10.254; "
    #         "sleep infinity"
    #         "\""
    #     ),
    # }

    for entry in host_entries(zones, hosts_per_zone):
        services[entry["name"]] = make_host_service(entry)
        services[f"{entry['name']}_route"] = make_route_service(entry["name"], entry["gw_addr"])

    net_filter = " or ".join(f"net {s}" for s in all_subnets) if all_subnets else "ip"

    services["capture"] = {
        "image": ROUTE_IMAGE,
        "container_name": "master-thesis-capture",
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

    return {"services": services, "networks": networks}


def load_topology_config(path: str, ap: argparse.ArgumentParser):
    with open(path, "r", encoding="utf-8") as f:
        topo = json.load(f)

    # dns_names = load_emulated_dns_names(topo)

    zones = topo.get("zones")
    hosts_per_zone = topo.get("hosts_per_zone")

    if not isinstance(zones, int):
        ap.error("'zones' in topology file must be an integer")
    if not isinstance(hosts_per_zone, list) or not all(isinstance(x, int) for x in hosts_per_zone):
        ap.error("'hosts_per_zone' in topology file must be a list of integers")
    if len(hosts_per_zone) != zones:
        ap.error(f"Topology mismatch: zones={zones} but hosts_per_zone has {len(hosts_per_zone)} entries")

    return zones, parse_hosts_per_zone(",".join(map(str, hosts_per_zone)), zones)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zones", type=int, help="Number of zones (includes A). Example: 4 => A,B,C,D")
    ap.add_argument("--hosts-per-zone", type=str, help="Comma-separated host counts for zones A,B,C,... Example: 2,3,1,0")
    ap.add_argument("--topology", type=str, help="Path to simulated_topology.json")
    ap.add_argument("--pcap", default="gateway.pcap")
    ap.add_argument("--out", default="docker-compose.yml")
    args = ap.parse_args()

    if args.topology:
        zones, hosts_per_zone = load_topology_config(args.topology, ap)
    else:
        if args.zones is None or args.hosts_per_zone is None:
            ap.error("Either provide --topology or both --zones and --hosts-per-zone")
        zones = args.zones
        hosts_per_zone = parse_hosts_per_zone(args.hosts_per_zone, zones)
        # dns_names = []

    compose = make_compose(zones, hosts_per_zone, args.pcap)
    Path(args.out).write_text(
        yaml.safe_dump(compose, sort_keys=False, indent=2, width=120),
        encoding="utf-8",
    )
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()