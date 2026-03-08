#!/usr/bin/env python3
from __future__ import annotations

import argparse
import string
from pathlib import Path
from typing import Any, Dict, List

import yaml

DEFAULT_HOST_IMAGE = "mcr.microsoft.com/powershell:windowsservercore-ltsc2022"

A_OCTET2_BASE = 30
A_SERVER_OCTET3 = 10
HOST_OCTET3_START = 11  # host_01 -> 11, host_02 -> 12, ...

SERVER_HOST_OCTET4 = 10
GATEWAY_HOST_OCTET4 = 1


def zone_letters(n: int) -> List[str]:
    if n < 1:
        raise ValueError("zones must be >= 1 (Zone A must exist)")
    if n > 26:
        raise ValueError("supports up to 26 zones (A-Z)")
    return list(string.ascii_uppercase[:n])


def parse_hosts_per_zone(s: str, zones: int) -> List[int]:
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if len(parts) != zones:
        raise ValueError(f"--hosts-per-zone must have exactly {zones} integers (for zones A..)")
    counts = [int(p) for p in parts]

    if any(c < 0 for c in counts):
        raise ValueError("host counts must be >= 0")
    if any(c > 200 for c in counts):
        raise ValueError("host counts must be <= 200")

    for zi, c in enumerate(counts):
        if c == 0:
            continue
        end = HOST_OCTET3_START + c - 1
        if end > 253:
            z = string.ascii_uppercase[zi]
            raise ValueError(f"Zone {z}: host subnet range exceeds .253")

    return counts


def subnet(o2: int, o3: int) -> str:
    return f"172.{o2}.{o3}.0/24"


def gw_ip(o2: int, o3: int) -> str:
    return f"172.{o2}.{o3}.{GATEWAY_HOST_OCTET4}"


def server_ip(o2: int, o3: int) -> str:
    return f"172.{o2}.{o3}.{SERVER_HOST_OCTET4}"


def host_ip(o2: int, o3: int) -> str:
    return f"172.{o2}.{o3}.{o3}"


def net_name_a_server() -> str:
    return "A_server_net"


def net_name_a_internal(i: int) -> str:
    return f"A_internal_host_{i:02d}_net"


def net_name_external(zone: str, i: int) -> str:
    return f"{zone}_external_host_{i:02d}_net"


def svc_name(zone: str, i: int) -> str:
    if zone == "A":
        return f"A_internal_host_{i:02d}"
    return f"{zone}_external_host_{i:02d}"


def make_http_listener_command() -> str:
    return (
        'powershell -NoLogo -NoProfile -Command "'
        "$$ErrorActionPreference='Stop'; "
        "$$listener = [System.Net.HttpListener]::new(); "
        "$$listener.Prefixes.Add('http://+:80/'); "
        "$$listener.Start(); "
        "Write-Host 'HTTP server listening on :80'; "
        "while ($$true) { "
        "  $$ctx = $$listener.GetContext(); "
        "  $$resp = $$ctx.Response; "
        "  $$bytes = [System.Text.Encoding]::ASCII.GetBytes('ok'); "
        "  $$resp.StatusCode = 200; "
        "  $$resp.ContentType = 'text/plain'; "
        "  $$resp.ContentLength64 = $$bytes.Length; "
        "  $$resp.OutputStream.Write($$bytes, 0, $$bytes.Length); "
        "  $$resp.OutputStream.Close(); "
        "} "
        '"'
    )


def make_host_keepalive_command() -> str:
    return (
        'powershell -NoLogo -NoProfile -Command '
        '"Write-Host \'Host ready\'; while ($$true) { Start-Sleep -Seconds 3600 }"'
    )


def build_nat_network(subnet_cidr: str, gateway_ip: str) -> Dict[str, Any]:
    return {
        "driver": "nat",
        "ipam": {
            "config": [{
                "subnet": subnet_cidr,
                "gateway": gateway_ip,
            }]
        },
    }


def make_compose(
    num_zones: int,
    hosts_per_zone: List[int],
    host_image: str,
    expose_server: bool,
) -> Dict[str, Any]:
    zones = zone_letters(num_zones)

    compose: Dict[str, Any] = {
        "name": "master-thesis",
        "services": {},
        "networks": {},
    }

    services: Dict[str, Any] = compose["services"]
    networks: Dict[str, Any] = compose["networks"]

    for zi, z in enumerate(zones):
        o2 = A_OCTET2_BASE + zi
        host_count = hosts_per_zone[zi]

        if z == "A":
            networks[net_name_a_server()] = build_nat_network(
                subnet_cidr=subnet(o2, A_SERVER_OCTET3),
                gateway_ip=gw_ip(o2, A_SERVER_OCTET3),
            )

            for i in range(1, host_count + 1):
                o3 = HOST_OCTET3_START + (i - 1)
                networks[net_name_a_internal(i)] = build_nat_network(
                    subnet_cidr=subnet(o2, o3),
                    gateway_ip=gw_ip(o2, o3),
                )
        else:
            for i in range(1, host_count + 1):
                o3 = HOST_OCTET3_START + (i - 1)
                networks[net_name_external(z, i)] = build_nat_network(
                    subnet_cidr=subnet(o2, o3),
                    gateway_ip=gw_ip(o2, o3),
                )

    a_o2 = A_OCTET2_BASE
    srv_ip = server_ip(a_o2, A_SERVER_OCTET3)

    server_service: Dict[str, Any] = {
        "image": host_image,
        "container_name": "master-thesis-server",
        "networks": {
            net_name_a_server(): {
                "ipv4_address": srv_ip
            }
        },
        "command": make_http_listener_command(),
    }

    if expose_server:
        server_service["ports"] = ["8080:80"]

    services["server"] = server_service

    for zi, z in enumerate(zones):
        o2 = A_OCTET2_BASE + zi
        host_count = hosts_per_zone[zi]

        for i in range(1, host_count + 1):
            o3 = HOST_OCTET3_START + (i - 1)
            name = svc_name(z, i)
            ip_addr = host_ip(o2, o3)

            if z == "A":
                zone_net = net_name_a_internal(i)
            else:
                zone_net = net_name_external(z, i)

            services[name] = {
                "image": host_image,
                "container_name": f"master-thesis-{name}",
                "depends_on": ["server"],
                "command": make_host_keepalive_command(),
                "networks": {
                    zone_net: {
                        "ipv4_address": ip_addr
                    }
                },
                "extra_hosts": [
                    f"api.ipify.org:{srv_ip}",
                    f"ipify.org:{srv_ip}",
                    f"github.com:{srv_ip}",
                ],
                "labels": {
                    "thesis.zone": z,
                    "thesis.role": "internal" if z == "A" else "external",
                },
            }

    return compose


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate Windows docker-compose with fixed per-host subnets for Windows VM use."
    )
    ap.add_argument(
        "--zones",
        type=int,
        required=True,
        help="Number of zones (includes A). Example: 1 => A",
    )
    ap.add_argument(
        "--hosts-per-zone",
        type=str,
        required=True,
        help="Comma-separated host counts for zones A,B,C,... Example: 1 or 2,1,0",
    )
    ap.add_argument(
        "--image",
        default=DEFAULT_HOST_IMAGE,
        help="Image for all Windows containers",
    )
    ap.add_argument(
        "--expose-server",
        action="store_true",
        help="Publish 8080:80 on the Windows VM host",
    )
    ap.add_argument(
        "--out",
        default="docker-compose.windows.yml",
        help="Output compose filename",
    )

    args = ap.parse_args()

    hosts_per_zone = parse_hosts_per_zone(args.hosts_per_zone, args.zones)

    compose = make_compose(
        num_zones=args.zones,
        hosts_per_zone=hosts_per_zone,
        host_image=args.image,
        expose_server=args.expose_server,
    )

    Path(args.out).write_text(
        yaml.safe_dump(compose, sort_keys=False, indent=2, width=120),
        encoding="utf-8",
    )
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()