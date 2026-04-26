#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, random, shutil, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXTRACT = ROOT / "extract_topology.py"
COMPOSE_GEN = ROOT / "generate_compose.py"
REPLAY = ROOT / "replay_traffic.py"
SET_DELAY = ROOT / "set_delay.sh"
LABEL_ZEEK = ROOT / "label_zeek.py"

TOPOLOGY = ROOT / "simulated_topology.json"
TOPOLOGY_RAW = ROOT / "topology.json"
COMPOSE = ROOT / "docker-compose.yml"

TMP = [
    TOPOLOGY, TOPOLOGY_RAW, COMPOSE,
    ROOT / "sender_capture.pcap",
    ROOT / "gateway_capture.pcap",
    ROOT / "gateway_egress.pcap",
    ROOT / "conn.log",
    ROOT / "conn.log.json",
    ROOT / "labeled_conn.csv",
]

# profile_id, min_delay_ms, max_delay_ms
# original = no gateway delay
PROFILES = {
    "original": (0, None, None),
    "low": (1, 10, 200),
    "medium": (2, 200, 600),
    "high": (3, 600, 1200),
}


def run(cmd, cwd=ROOT, quiet=False):
    cmd = list(map(str, cmd))
    if cmd[0] == "python3":
        cmd[0] = sys.executable
    if not quiet:
        print("$ " + " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def compose_down():
    subprocess.run(
        ["docker", "compose", "down", "-v"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def clean_tmp():
    for p in TMP:
        if p.exists() or p.is_symlink():
            p.unlink()


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def copy_if_exists(src, dst):
    src = Path(src)
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def find_pcaps(datasets):
    for folder in sorted(Path(datasets).iterdir()):
        if not folder.is_dir():
            continue

        label = "benign" if folder.name.lower() == "benign" else "malicious"
        attack = "" if label == "benign" else folder.name

        for pcap in sorted(folder.rglob("*.pcap")):
            yield pcap.resolve(), label, attack


def replay_copy(src, out_dir, sample_id):
    dst = out_dir / f"{sample_id}.pcap"
    if dst.exists() or dst.is_symlink():
        dst.unlink()
    shutil.copy2(src, dst)
    return dst


def sender_row(topology):
    by_ip = {r["original_ip"]: r for r in topology["mapping"] if r.get("original_ip")}
    scores = {}

    for e in topology.get("edges", []):
        row = by_ip.get(e.get("src_original_ip"))
        if not row:
            continue
        if row.get("sim_type") != "internal":
            continue
        if row.get("service_name") in {"gw", "dns"}:
            continue

        ip = row["original_ip"]
        scores[ip] = scores.get(ip, 0) + int(e.get("packet_count", 0))

    if not scores:
        raise RuntimeError("Could not detect sender from topology.")

    return by_ip[max(scores, key=scores.get)]


def delay_pairs(topology, count):
    sender_ip = sender_row(topology)["simulated_ip"]

    dests = sorted({
        r["simulated_ip"]
        for r in topology.get("mapping", [])
        if r.get("simulated_ip")
        and r["simulated_ip"] != sender_ip
        and r.get("sim_type") not in {"ignore", "gateway"}
    })

    selected = random.sample(dests, min(count, len(dests)))

    pairs = []
    for dst in selected:
        pairs.append((sender_ip, dst))
        pairs.append((dst, sender_ip))

    return sender_ip, selected, pairs


def write_original_profile(topology, out_dir, count):
    sender_ip = sender_row(topology)["simulated_ip"]

    info = {
        "profile": "original",
        "delay_ms": 0,
        "gateway_delay_enabled": False,
        "sender_ip": sender_ip,
        "requested_destinations": count,
        "selected_destinations": [],
        "bidirectional": False,
        "pairs": [],
        "note": "Original replay timing only. No tc/netem gateway delay was applied.",
    }

    (out_dir / "delay_profile.json").write_text(
        json.dumps(info, indent=2),
        encoding="utf-8",
    )

    print("[*] Delay profile        : original")
    print("[*] Delay value          : 0 ms")
    print("[*] Gateway delay        : disabled")


def apply_delay(topology, profile, out_dir, count):
    if profile == "original":
        write_original_profile(topology, out_dir, count)
        return

    _, lo, hi = PROFILES[profile]
    delay_ms = random.randint(lo, hi)
    sender_ip, selected, pairs = delay_pairs(topology, count)

    info = {
        "profile": profile,
        "delay_ms": delay_ms,
        "gateway_delay_enabled": True,
        "sender_ip": sender_ip,
        "requested_destinations": count,
        "selected_destinations": selected,
        "bidirectional": True,
        "pairs": [{"src_ip": s, "dst_ip": d} for s, d in pairs],
    }

    (out_dir / "delay_profile.json").write_text(
        json.dumps(info, indent=2),
        encoding="utf-8",
    )

    print(f"[*] Delay profile        : {profile}")
    print(f"[*] Delay value          : {delay_ms} ms")
    print(f"[*] Delayed destinations : {len(selected)}")
    print(f"[*] Directional rules    : {len(pairs)}")

    for src, dst in pairs:
        run([SET_DELAY, "set", src, dst, delay_ms], quiet=True)


def save_runtime_files(out_dir):
    copy_if_exists(TOPOLOGY, out_dir / "simulated_topology.json")
    copy_if_exists(TOPOLOGY_RAW, out_dir / "topology.json")
    copy_if_exists(COMPOSE, out_dir / "docker-compose.yml")


def run_zeek(pcap, out_dir, gt):
    if not LABEL_ZEEK.exists():
        print("[!] label_zeek.py not found, skipping Zeek")
        return

    zeek_dir = out_dir / "zeek"
    zeek_dir.mkdir(parents=True, exist_ok=True)

    run([
        "zeek", "-b", "-C",
        "-r", pcap,
        "base/protocols/conn",
        "LogAscii::use_json=T",
    ], cwd=zeek_dir, quiet=True)

    conn = zeek_dir / "conn.log"
    if conn.exists():
        run(["python3", LABEL_ZEEK, gt, conn, zeek_dir / "labeled_conn.csv"])


def process_one(pcap, label, attack, profile, args):
    profile_id = PROFILES[profile][0]
    sample_id = f"{pcap.stem}_{profile_id}"
    out_dir = args.results / label / sample_id
    out_dir.mkdir(parents=True, exist_ok=True)

    replay_pcap = replay_copy(pcap, out_dir, sample_id)

    print("\n" + "=" * 80)
    print(f"[+] PCAP                 : {pcap.name}")
    print(f"[+] Sample ID            : {sample_id}")
    print(f"[+] Label                : {label}")
    print(f"[+] Attack class         : {attack or '(none)'}")
    print(f"[+] Timing profile       : {profile}")
    print(f"[+] Multiplier           : {args.multiplier}")
    print(f"[+] Output               : {out_dir}")
    print("=" * 80)

    clean_tmp()
    compose_down()

    try:
        run(["python3", EXTRACT, pcap])
        topology = load_json(TOPOLOGY)

        run(["python3", COMPOSE_GEN, "--topology", TOPOLOGY, "--out", COMPOSE])
        run(["docker", "compose", "up", "-d"])
        time.sleep(args.boot_wait)

        apply_delay(topology, profile, out_dir, args.delay_count)

        gt = args.results / "ground_truth.csv"

        cmd = [
            "python3", REPLAY,
            "--pcap", replay_pcap,
            "--topology", TOPOLOGY,
            "--multiplier", args.multiplier,
            "--ground-truth", gt,
            "--capture-pre-out", out_dir / "sender_capture.pcap",
            "--capture-out", out_dir / "gateway_capture.pcap",
            "--clean-out", out_dir / "gateway_egress.pcap",
        ]

        if attack:
            cmd += ["--attack-class", attack]

        run(cmd)
        save_runtime_files(out_dir)

        if args.zeek:
            run_zeek(out_dir / "gateway_egress.pcap", out_dir, gt)

    finally:
        compose_down()
        clean_tmp()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets", default=str(ROOT / "datasets"))
    ap.add_argument("--results", default=str(ROOT / "results"))
    ap.add_argument("--multiplier", type=float, default=1.0)
    ap.add_argument("--delay-count", type=int, default=2)
    ap.add_argument("--boot-wait", type=float, default=2.0)
    ap.add_argument("--zeek", action="store_true")
    ap.add_argument("--seed", type=int)
    args = ap.parse_args()

    args.datasets = Path(args.datasets).resolve()
    args.results = Path(args.results).resolve()
    args.results.mkdir(parents=True, exist_ok=True)

    if args.seed is not None:
        random.seed(args.seed)

    pcaps = list(find_pcaps(args.datasets))
    if not pcaps:
        sys.exit(f"ERROR: no pcap files found in {args.datasets}")

    print(f"[*] Found pcaps          : {len(pcaps)}")
    print(f"[*] Timing profiles      : {', '.join(PROFILES.keys())}")

    for pcap, label, attack in pcaps:
        for profile in PROFILES:
            process_one(pcap, label, attack, profile, args)

    print("\n[+] Dataset generation finished.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        compose_down()
        clean_tmp()
        sys.exit("\nInterrupted.")
    except Exception as e:
        compose_down()
        clean_tmp()
        sys.exit(f"\nERROR: {e}")