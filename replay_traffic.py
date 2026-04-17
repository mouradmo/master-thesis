#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

DOCKER_PREFIX = "master-thesis-"
TCPREPLAY_IMAGE = "local/tcpreplay"


def run(cmd: List[str], check: bool = True, capture_output: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        capture_output=capture_output,
    )


def docker_exec(container: str, shell_cmd: str) -> str:
    cp = run(["docker", "exec", container, "sh", "-lc", shell_cmd])
    return cp.stdout.strip()


def load_topology(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def mapping_by_original_ip(topology: Dict) -> Dict[str, Dict]:
    out: Dict[str, Dict] = {}
    for row in topology.get("mapping", []):
        ip = row.get("original_ip")
        if ip:
            out[ip] = row
    return out


def build_rewrite_maps(topology: Dict) -> Tuple[str, str]:
    pairs = []
    for row in topology.get("mapping", []):
        orig = row.get("original_ip")
        sim = row.get("simulated_ip")
        if not orig or not sim:
            continue
        pairs.append(f"{orig}:{sim}")

    if not pairs:
        raise ValueError("No usable IP mappings found in topology.")

    joined = ",".join(pairs)
    return joined, joined


def auto_detect_sender_row(topology: Dict) -> Dict:
    by_ip = mapping_by_original_ip(topology)
    scores: Dict[str, int] = defaultdict(int)

    for edge in topology.get("edges", []):
        src_ip = edge.get("src_original_ip")
        dst_service = edge.get("dst_service")
        packet_count = int(edge.get("packet_count", 0))

        if not src_ip or src_ip not in by_ip:
            continue

        row = by_ip[src_ip]
        sim_type = row.get("sim_type")
        service_name = row.get("service_name")

        if sim_type != "internal":
            continue

        if service_name in {"gw", "dns"}:
            continue

        if dst_service is not None:
            scores[src_ip] += packet_count * 10
        else:
            scores[src_ip] += packet_count

    if not scores:
        raise ValueError(
            "Could not auto-detect a sender host from topology edges. "
            "No suitable internal replay source was found."
        )

    sender_ip = max(scores, key=scores.get)
    return by_ip[sender_ip]


def ensure_tcpreplay_image() -> None:
    probe = subprocess.run(
        ["docker", "image", "inspect", TCPREPLAY_IMAGE],
        text=True,
        capture_output=True,
    )
    if probe.returncode == 0:
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        dockerfile = Path(tmpdir) / "Dockerfile"
        dockerfile.write_text(
            "FROM alpine:3.20\n"
            "RUN apk add --no-cache tcpreplay\n"
            'ENTRYPOINT ["tcpreplay"]\n',
            encoding="utf-8",
        )
        print("[*] Building local tcpreplay helper image...")
        subprocess.run(
            ["docker", "build", "-t", TCPREPLAY_IMAGE, tmpdir],
            check=True,
        )


def discover_interface(container: str, gateway_ip: str) -> str:
    cmd = (
        f"ip route get {gateway_ip} | "
        r"""awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'"""
    )
    iface = docker_exec(container, cmd)
    if not iface:
        raise RuntimeError(f"Could not discover interface in {container} for gateway {gateway_ip}")
    return iface


def rewrite_pcap(
    pcap_in: str,
    pcap_out: str,
    srcipmap: str,
    dstipmap: str,
) -> None:
    cmd = [
        "tcprewrite",
        f"--infile={pcap_in}",
        f"--outfile={pcap_out}",
        f"--srcipmap={srcipmap}",
        f"--dstipmap={dstipmap}",
        "--fixcsum",
    ]
    print("[*] Rewriting pcap...")
    subprocess.run(cmd, check=True)


def replay_from_namespace(container: str, iface: str, rewritten_pcap: str, multiplier: float) -> None:
    pwd = os.getcwd()
    pcap_name = os.path.basename(rewritten_pcap)

    cmd = [
        "docker", "run", "--rm",
        "--network", f"container:{container}",
        "--cap-add", "NET_ADMIN",
        "--cap-add", "NET_RAW",
        "-v", f"{pwd}:/work",
        TCPREPLAY_IMAGE,
        f"--intf1={iface}",
        f"--multiplier={multiplier}",
        f"/work/{pcap_name}",
    ]

    print("[*] Replaying from sender namespace with original packet timing...")
    subprocess.run(cmd, check=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="Original pcap file")
    ap.add_argument("--topology", required=True, help="simulated_topology.json")
    ap.add_argument("--rewritten", default="", help="Output rewritten pcap path")
    ap.add_argument("--multiplier", type=float, default=1.0, help="Replay timing multiplier; 1.0 = original timing")
    args = ap.parse_args()

    topology = load_topology(args.topology)
    sender_row = auto_detect_sender_row(topology)

    sender_original_ip = sender_row.get("original_ip")
    service_name = sender_row.get("service_name")
    gateway_ip = sender_row.get("gateway_ip")
    simulated_ip = sender_row.get("simulated_ip")

    if not sender_original_ip or not service_name or not gateway_ip or not simulated_ip:
        raise ValueError(f"Auto-detected sender row is missing required fields: {sender_row}")

    sender_container = DOCKER_PREFIX + service_name
    rewritten = args.rewritten or (Path(args.pcap).stem + "_rewritten.pcap")

    print(f"[*] Sender original IP : {sender_original_ip}")
    print(f"[*] Sender simulated IP: {simulated_ip}")
    print(f"[*] Sender container   : {sender_container}")
    print(f"[*] Sender gateway IP  : {gateway_ip}")

    srcipmap, dstipmap = build_rewrite_maps(topology)

    iface = discover_interface(sender_container, gateway_ip)
    print(f"[*] Interface          : {iface}")

    rewrite_pcap(
        pcap_in=args.pcap,
        pcap_out=rewritten,
        srcipmap=srcipmap,
        dstipmap=dstipmap,
    )

    ensure_tcpreplay_image()
    replay_from_namespace(sender_container, iface, rewritten, args.multiplier)

    print(f"\n[+] Rewritten pcap: {rewritten}")
    print("[+] Replay finished.")
    print("[+] Capture should already be handled by docker-compose (gateway.pcap).")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)