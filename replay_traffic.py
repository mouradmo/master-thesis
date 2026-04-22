#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DOCKER_PREFIX = "master-thesis-"
TCPREPLAY_IMAGE = "local/tcpreplay"
GW_CONTAINER = f"{DOCKER_PREFIX}gw"
GW_CAPTURE_TMP = "/tmp/replay_traffic_gateway.pcap"

GROUND_TRUTH_FIELDS = [
    "execution_id", "sample_id", "attack_class", "traffic_label",
    "original_sender_ip", "mapped_sender_ip", "sender_container", "sender_interface",
    "replay_start_time_utc", "replay_end_time_utc", "replay_multiplier",
    "status", "notes",
]


def run(cmd, **kwargs):
    return subprocess.run(cmd, text=True, capture_output=True, check=True, **kwargs)


def docker_exec(container, shell_cmd):
    return run(["docker", "exec", container, "sh", "-lc", shell_cmd]).stdout.strip()


def now_utc():
    return datetime.now(timezone.utc)


def fmt_utc(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def mapping_by_original_ip(topology):
    return {row["original_ip"]: row for row in topology.get("mapping", []) if row.get("original_ip")}


def build_rewrite_map(topology):
    pairs = [
        f'{row["original_ip"]}:{row["simulated_ip"]}'
        for row in topology.get("mapping", [])
        if row.get("original_ip") and row.get("simulated_ip")
    ]
    if not pairs:
        raise ValueError("No usable IP mappings found in topology.")
    return ",".join(pairs)


def auto_detect_sender_row(topology):
    by_ip = mapping_by_original_ip(topology)
    scores = defaultdict(int)

    for edge in topology.get("edges", []):
        src_ip = edge.get("src_original_ip")
        row = by_ip.get(src_ip)
        if not row or row.get("sim_type") != "internal" or row.get("service_name") in {"gw", "dns"}:
            continue
        pkt_count = int(edge.get("packet_count", 0))
        scores[src_ip] += pkt_count * (10 if edge.get("dst_service") is not None else 1)

    if not scores:
        raise ValueError("Could not auto-detect a replay sender host from topology.")

    return by_ip[max(scores, key=scores.get)]


def ensure_tcpreplay_image():
    exists = subprocess.run(
        ["docker", "image", "inspect", TCPREPLAY_IMAGE],
        text=True,
        capture_output=True,
    )
    if exists.returncode == 0:
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        dockerfile = Path(tmpdir) / "Dockerfile"
        dockerfile.write_text(
            "FROM alpine:3.20\n"
            "RUN apk add --no-cache tcpreplay\n"
            'ENTRYPOINT ["tcpreplay"]\n',
            encoding="utf-8",
        )
        print("[*] Building local tcpreplay image...")
        subprocess.run(["docker", "build", "-t", TCPREPLAY_IMAGE, tmpdir], check=True)


def route_iface(container, target_ip):
    cmd = (
        f"ip route get {target_ip} | "
        "awk '{for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1); exit}}'"
    )
    return docker_exec(container, cmd)


def discover_interface(container, target_ip):
    for candidate in (f"{container}-route", container):
        try:
            iface = route_iface(candidate, target_ip)
            if iface:
                return iface
        except Exception:
            pass
    raise RuntimeError(f"Could not discover interface for {container} towards {target_ip}")


def discover_gateway_interface(target_ip):
    iface = route_iface(GW_CONTAINER, target_ip)
    if not iface:
        raise RuntimeError(f"Could not discover gateway interface towards {target_ip}")
    return iface


def cleanup_gateway_capture():
    docker_exec(GW_CONTAINER, f"rm -f {GW_CAPTURE_TMP} /tmp/replay_traffic_gateway.log")


def start_gateway_capture(iface):
    cmd = (
        f"nohup tcpdump -U -i {iface} -nn -s 0 not arp "
        f"-w {GW_CAPTURE_TMP} >/tmp/replay_traffic_gateway.log 2>&1 & echo $!"
    )
    pid = docker_exec(GW_CONTAINER, cmd)
    if not pid:
        raise RuntimeError("Failed to start gateway capture.")
    return pid


def stop_gateway_capture(pid):
    if pid:
        docker_exec(GW_CONTAINER, f"kill {pid} 2>/dev/null || true")


def copy_gateway_capture(output_path):
    out = Path(output_path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["docker", "cp", f"{GW_CONTAINER}:{GW_CAPTURE_TMP}", str(out)], check=True)
    return out


def rewrite_pcap(pcap_in, pcap_out, rewrite_map):
    pcap_in = Path(pcap_in).expanduser().resolve()
    pcap_out = Path(pcap_out).expanduser().resolve()

    if not pcap_in.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_in}")

    print("[*] Rewriting pcap...")
    subprocess.run(
        [
            "tcprewrite",
            f"--infile={pcap_in}",
            f"--outfile={pcap_out}",
            f"--srcipmap={rewrite_map}",
            f"--dstipmap={rewrite_map}",
            "--fixcsum",
        ],
        check=True,
    )
    return pcap_out


def replay_from_namespace(container, iface, pcap_path, multiplier):
    print("[*] Replaying from sender namespace...")
    subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", f"container:{container}",
            "--cap-add", "NET_ADMIN",
            "--cap-add", "NET_RAW",
            "-v", f"{pcap_path.parent}:/work",
            TCPREPLAY_IMAGE,
            f"--intf1={iface}",
            f"--multiplier={multiplier}",
            f"/work/{pcap_path.name}",
        ],
        check=True,
    )


def next_execution_id(path):
    gt = Path(path)
    if not gt.exists():
        return "1"

    max_id = 0
    with gt.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            raw = str(row.get("execution_id", "")).strip()
            if raw.isdigit():
                max_id = max(max_id, int(raw))
    return str(max_id + 1)


def append_ground_truth(path, row):
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    exists = out.exists()

    with out.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=GROUND_TRUTH_FIELDS)
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def make_ground_truth_row(ground_truth_path, pcap_path, sender_row, sender_container,
                          iface, multiplier, attack_class, start_time, end_time, status, notes):
    attack_class = attack_class.strip()
    return {
        "execution_id": next_execution_id(ground_truth_path),
        "sample_id": Path(pcap_path).stem,
        "attack_class": attack_class,
        "traffic_label": "benign" if not attack_class else "malicious",
        "original_sender_ip": str(sender_row.get("original_ip", "")),
        "mapped_sender_ip": str(sender_row.get("simulated_ip", "")),
        "sender_container": sender_container,
        "sender_interface": iface,
        "replay_start_time_utc": fmt_utc(start_time),
        "replay_end_time_utc": fmt_utc(end_time),
        "replay_multiplier": str(multiplier),
        "status": status,
        "notes": notes,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="Original pcap file")
    ap.add_argument("--topology", default="simulated_topology.json")
    ap.add_argument("--rewritten", default="")
    ap.add_argument("--multiplier", type=float, default=1.0)
    ap.add_argument("--ground-truth", default="ground_truth.csv")
    ap.add_argument("--attack-class", default="")
    ap.add_argument("--notes", default="")
    ap.add_argument("--capture-out", default="replay_traffic_gateway.pcap")
    args = ap.parse_args()

    topology = load_json(args.topology)
    sender_row = auto_detect_sender_row(topology)

    original_ip = sender_row.get("original_ip")
    simulated_ip = sender_row.get("simulated_ip")
    service_name = sender_row.get("service_name")
    gateway_ip = sender_row.get("gateway_ip")
    if not all([original_ip, simulated_ip, service_name, gateway_ip]):
        raise ValueError(f"Auto-detected sender row is incomplete: {sender_row}")

    sender_container = DOCKER_PREFIX + service_name
    rewritten_path = Path(args.rewritten or f"{Path(args.pcap).stem}_rewritten.pcap").expanduser().resolve()
    attack_class = args.attack_class.strip()
    traffic_label = "benign" if not attack_class else "malicious"

    print(f"[*] Sender original IP : {original_ip}")
    print(f"[*] Sender simulated IP: {simulated_ip}")
    print(f"[*] Sender container   : {sender_container}")
    print(f"[*] Sender gateway IP  : {gateway_ip}")
    print(f"[*] Attack class       : {attack_class or '(empty)'}")
    print(f"[*] Traffic label      : {traffic_label}")
    print(f"[*] Ground truth file  : {args.ground_truth}")
    print(f"[*] Gateway capture out: {args.capture_out}")

    iface = gateway_iface = capture_pid = ""
    start_time = None
    status = "failed"
    notes = args.notes.strip()

    try:
        iface = discover_interface(sender_container, gateway_ip)
        print(f"[*] Sender interface   : {iface}")

        gateway_iface = discover_gateway_interface(simulated_ip)
        print(f"[*] Gateway interface  : {gateway_iface}")

        rewritten_path = rewrite_pcap(args.pcap, str(rewritten_path), build_rewrite_map(topology))
        ensure_tcpreplay_image()

        cleanup_gateway_capture()
        capture_pid = start_gateway_capture(gateway_iface)
        print(f"[*] Started gateway capture on {gateway_iface} (pid={capture_pid})")

        time.sleep(1)
        start_time = now_utc()
        replay_from_namespace(sender_container, iface, rewritten_path, args.multiplier)
        status = "completed"

    except Exception as exc:
        err = f"replay_error={exc}"
        notes = f"{notes}; {err}" if notes else err
        raise

    finally:
        end_time = now_utc()
        start_time = start_time or end_time

        try:
            if capture_pid:
                time.sleep(1)
                stop_gateway_capture(capture_pid)
                print(f"[*] Stopped gateway capture pid={capture_pid}")
                copied = copy_gateway_capture(args.capture_out)
                print(f"[*] Gateway replay capture saved to: {copied}")
        except Exception as exc:
            warn = f"capture_export_error={exc}"
            notes = f"{notes}; {warn}" if notes else warn
            print(f"[!] Warning: {warn}")

        row = make_ground_truth_row(
            args.ground_truth, args.pcap, sender_row, sender_container, iface,
            args.multiplier, attack_class, start_time, end_time, status, notes
        )
        append_ground_truth(args.ground_truth, row)
        print(f"[*] Ground truth row appended to: {args.ground_truth}")

        try:
            cleanup_gateway_capture()
        except Exception:
            pass

        try:
            if rewritten_path.exists():
                rewritten_path.unlink()
                print(f"[*] Deleted temporary file: {rewritten_path}")
        except Exception as exc:
            print(f"[!] Warning: could not delete {rewritten_path}: {exc}")

    print("\n[+] Replay finished.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)