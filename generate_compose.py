#!/usr/bin/env python3
from __future__ import annotations

import argparse
import string
from pathlib import Path
from typing import Any, Dict, List
import json

import yaml

GW_HOST_OCTET4 = 254

A_OCTET2_BASE = 30
A_SERVER_OCTET3 = 10
HOST_OCTET3_START = 11  # host_01 -> 11 (=> .11.11), host_02 -> 12, ...
CORE_DNS_IP = "172.30.10.53"
# Linux image for external hosts
EXTERNAL_IMAGE_NAME = "nicolaka/netshoot:latest"


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
            raise ValueError(
                f"Zone {z}: host octet3 range exceeds .253 "
                f"(start={HOST_OCTET3_START}, count={c})"
            )

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
    
def load_emulated_dns_names(topo: Dict[str, Any]) -> List[str]:
    names = topo.get("dns_names", [])
    if not isinstance(names, list):
        return []

    cleaned = []
    seen = set()

    for name in names:
        if not isinstance(name, str):
            continue

        name = name.strip().lower().rstrip(".")
        if not name:
            continue

        if name in {"wpad", "wpad.local"}:
            continue
        if name.endswith(".local"):
            continue

        if name not in seen:
            seen.add(name)
            cleaned.append(name)

    return cleaned


def make_compose(
    num_zones: int,
    hosts_per_zone: List[int],
    pcap_filename: str,
    dns_names: List[str] | None = None,
) -> Dict[str, Any]:
    zones = zone_letters(num_zones)

    compose: Dict[str, Any] = {"services": {}, "networks": {}}
    services: Dict[str, Any] = compose["services"]
    networks: Dict[str, Any] = compose["networks"]

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

    base_dns_names = [
        "server.local",
        "c2.local",
        "api.ipify.org",
        "ipify.org",
        "github.com",
    ]

    all_dns_names: List[str] = []
    seen_dns = set()

    for name in base_dns_names + (dns_names or []):
        name = name.strip().lower().rstrip(".")
        if not name:
            continue
        if name not in seen_dns:
            seen_dns.add(name)
            all_dns_names.append(name)

    host_lines = "".join(f"        {server_ip} {name}\n" for name in all_dns_names)

    corefile_content = (
        ".:53 {\n"
        "    hosts {\n"
        f"{host_lines}"
        "        fallthrough\n"
        "    }\n"
        "    log\n"
        "    errors\n"
        "}\n"
    )
    Path("Corefile").write_text(corefile_content, encoding="utf-8")

    services["server"] = {
     "image": "nginx:alpine",
     "container_name": "master-thesis-server",
     "networks": {net_name_a_server(): {"ipv4_address": server_ip}},
     "command": (
        "sh -c \""
        "cat > /etc/nginx/conf.d/default.conf <<'EOF'\n"
        "server {\n"
        "  listen 80;\n"
        "  server_name server.local;\n"
        "\n"
        "  location = / {\n"
        "    default_type text/html;\n"
        "    return 200 '<html><body><h1>Internal test server</h1></body></html>\\\\n';\n"
        "  }\n"
        "\n"
        "  location = /health {\n"
        "    default_type text/plain;\n"
        "    return 200 'healthy\\\\n';\n"
        "  }\n"
        "\n"
        "  location = /index.html {\n"
        "    default_type text/html;\n"
        "    return 200 '<html><body><p>index page</p></body></html>\\\\n';\n"
        "  }\n"
        "}\n"
        "\n"
        "server {\n"
        "  listen 80;\n"
        "  server_name c2.local;\n"
        "\n"
        "  location = / {\n"
        "    default_type application/json;\n"
        "    return 200 '{\\\"status\\\":\\\"online\\\"}\\\\n';\n"
        "  }\n"
        "\n"
        "  location = /api/beacon {\n"
        "    default_type application/json;\n"
        "    return 200 '{\\\"cmd\\\":\\\"sleep\\\",\\\"seconds\\\":5}\\\\n';\n"
        "  }\n"
        "\n"
        "  location = /api/task {\n"
        "    default_type application/json;\n"
        "    return 200 '{\\\"task\\\":\\\"noop\\\"}\\\\n';\n"
        "  }\n"
        "}\n"
        "\n"
        "server {\n"
        "  listen 80;\n"
        "  server_name github.com pastefy.app;\n"        "\n"
        "  location = / {\n"
        "    default_type text/html;\n"
        "    return 200 '<html><body><h1>GitHub</h1></body></html>\\\\n';\n"
        "  }\n"
        "\n"
        "  location = /robots.txt {\n"
        "    default_type text/plain;\n"
        "    return 200 'User-agent: *\\\\nDisallow:\\\\n';\n"
        "  }\n"
        "}\n"
        "\n"
        "server {\n"
        "  listen 80;\n"
        "  server_name api.ipify.org ipify.org;\n"
        "\n"
        "  location = / {\n"
        "    default_type text/plain;\n"
        "    return 200 '203.0.113.10\\\\n';\n"
        "  }\n"
        "}\n"
        "\n"
        "server {\n"
        "  listen 80 default_server;\n"
        "  server_name _;\n"
        "\n"
        "  location / {\n"
        "    default_type text/plain;\n"
        "    return 200 'ok\\\\n';\n"
        "  }\n"
        "}\n"
        "EOF\n"
        "nginx -g 'daemon off;'\n"
        "\""
         ),
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
    services["dns"] = {
        "image": "coredns/coredns:latest",
        "container_name": "master-thesis-dns",
        "networks": {net_name_a_server(): {"ipv4_address": CORE_DNS_IP}},
        "volumes": ["./Corefile:/Corefile:ro"],
        "command": ["-conf", "/Corefile"],
     }
    services["dns_route"] = {
        "image": "nicolaka/netshoot:latest",
        "container_name": "master-thesis-dns-route",
        "network_mode": "service:dns",
        "depends_on": ["dns", "gw"],
        "cap_add": ["NET_ADMIN"],
        "command": (
            "sh -c \""
            "ip route del default 2>/dev/null || true; "
            "ip route add default via 172.30.10.254; "
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
                    "dns": [CORE_DNS_IP],
                    "dns_search": ["local"],
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
                    "image": EXTERNAL_IMAGE_NAME,
                    "container_name": f"master-thesis-{name}",
                    "command": "sleep infinity",
                    "dns": [CORE_DNS_IP],
                    "dns_search": ["local"],
                    "cap_add": ["NET_ADMIN", "NET_RAW"],
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

    ap.add_argument("--zones", type=int, help="Number of zones (includes A). Example: 4 => A,B,C,D")
    ap.add_argument(
        "--hosts-per-zone",
        type=str,
        help="Comma-separated host counts for zones A,B,C,... Example: 2,3,1,0",
    )
    ap.add_argument("--topology", type=str, help="Path to simulated_topology.json")
    ap.add_argument("--pcap", default="gateway.pcap")
    ap.add_argument("--out", default="docker-compose.yml")

    args = ap.parse_args()

    if args.topology:
        with open(args.topology, "r", encoding="utf-8") as f:
            topo = json.load(f)

        dns_names = load_emulated_dns_names(topo)

        if "zones" not in topo or "hosts_per_zone" not in topo:
            ap.error("--topology file must contain 'zones' and 'hosts_per_zone'")

        zones = topo["zones"]
        hosts_per_zone = topo["hosts_per_zone"]

        if not isinstance(zones, int):
            ap.error("'zones' in topology file must be an integer")

        if not isinstance(hosts_per_zone, list) or not all(isinstance(x, int) for x in hosts_per_zone):
            ap.error("'hosts_per_zone' in topology file must be a list of integers")

        if len(hosts_per_zone) != zones:
            ap.error(
                f"Topology mismatch: zones={zones} but hosts_per_zone has {len(hosts_per_zone)} entries"
            )

        hosts_per_zone = parse_hosts_per_zone(",".join(map(str, hosts_per_zone)), zones)

    else:
        if args.zones is None or args.hosts_per_zone is None:
            ap.error("Either provide --topology or both --zones and --hosts-per-zone")

        zones = args.zones
        hosts_per_zone = parse_hosts_per_zone(args.hosts_per_zone, zones)
        dns_names = []

    compose = make_compose(
        num_zones=zones,
        hosts_per_zone=hosts_per_zone,
        pcap_filename=args.pcap,
        dns_names=dns_names,

    )

    Path(args.out).write_text(
        yaml.safe_dump(compose, sort_keys=False, indent=2, width=120),
        encoding="utf-8",
    )
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()