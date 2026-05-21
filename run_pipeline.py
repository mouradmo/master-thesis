#!/usr/bin/env python3
from pathlib import Path
import json
import shutil
import subprocess
import sys
import random

GT = "ground_truth.csv"


def run(cmd, cwd=None):
    print("\n$ " + " ".join(map(str, cmd)))
    subprocess.run([str(x) for x in cmd], cwd=cwd, check=True)


def ask(msg, default=""):
    x = input(f"{msg}" + (f" [{default}]" if default else "") + ": ").strip()
    return x or default


def ask_choice(msg, choices, aliases=None):
    aliases = aliases or {}

    while True:
        x = ask(msg).lower()

        if x in aliases:
            return aliases[x]

        if x in choices:
            return x

        print("Choose:", ", ".join(sorted(choices | set(aliases.keys()))))


def cleanup_experiment_files():
    """
    Keep only important experiment outputs:
      - labeled_conn_*.csv
      - gateway_egress_*.pcap
      - ground_truth.csv

    Delete temporary/debug files.
    """

    files_to_delete = [
        "docker-compose.yml",
        "topology.json",
        "simulated_topology.json",
        "gateway_capture_any.pcap",
        "gateway.pcap",
    ]

    patterns_to_delete = [
        "gateway_iface_*.pcap",
        "zeek_gateway_egress_*",
        "zeek_*_base",
    ]

    for name in files_to_delete:
        p = Path(name)
        if p.exists():
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            print(f"[-] Removed {p}")

    for pattern in patterns_to_delete:
        for p in Path(".").glob(pattern):
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            print(f"[-] Removed {p}")


def zeek_and_label(pcap, out_csv):
    pcap = Path(pcap).resolve()
    zeek_dir = Path(f"zeek_{pcap.stem}")
    zeek_dir.mkdir(exist_ok=True)

    run([
        "zeek", "-b", "-C", "-r", str(pcap),
        "base/protocols/conn",
        "LogAscii::use_json=T",
    ], cwd=zeek_dir)

    conn = zeek_dir / "conn.log"
    run(["python3", "label_zeek.py", GT, str(conn), out_csv])


def process_base():
    pcap = Path(ask("Original/base PCAP path")).expanduser().resolve()

    label = ask_choice(
        "Label? benign(b) / malicious(m)",
        {"benign", "malicious"},
        {"b": "benign", "m": "malicious"},
    )

    out_csv = f"labeled_conn_{pcap.stem}_base.csv"

    try:
        run([
            "python3", "ground_truth_base.py",
            "--pcaps", pcap,
            "--label", label,
            "--ground-truth", GT,
        ])

        zeek_and_label(pcap, out_csv)

        print(f"[+] Done base -> {out_csv}")

    finally:
        cleanup_experiment_files()


def load_simulated_hosts(path="simulated_topology.json"):
    p = Path(path)
    if not p.exists():
        print("[!] simulated_topology.json not found")
        return []

    topo = json.loads(p.read_text(encoding="utf-8"))
    rows = []

    for r in topo.get("mapping", []):
        sim_ip = r.get("simulated_ip", "")
        service = r.get("service_name", "")
        sim_type = r.get("sim_type", "")
        original_ip = r.get("original_ip", "")

        if not sim_ip or sim_ip == "0.0.0.0":
            continue

        if sim_type in {"ignore", "gateway", "dhcp_zero"}:
            continue

        rows.append({
            "service": service,
            "simulated_ip": sim_ip,
            "original_ip": original_ip,
            "sim_type": sim_type,
        })

    return rows


def print_possible_delays():
    hosts = load_simulated_hosts()

    if not hosts:
        print("[!] No simulated hosts found for delay selection.")
        return

    print("\nPossible delay endpoints:")
    print("No.  simulated_ip       type        service              original_ip")
    print("---  ---------------    --------    ------------------   -----------")

    for i, h in enumerate(hosts, 1):
        print(
            f"{i:<4} {h['simulated_ip']:<16} "
            f"{h['sim_type']:<10} {h['service']:<20} {h['original_ip']}"
        )

    print("\nExample:")
    print("./set_delay.sh set 172.30.11.11 172.31.11.11 100")


def maybe_apply_delay():
    hosts = load_simulated_hosts()

    if not hosts:
        print("[!] No simulated hosts found for delay selection.")
        return

    use_delay = ask_choice(
        "Apply random gateway delays before replay? yes(y) / no(n)",
        {"yes", "no"},
        {"y": "yes", "n": "no"},
    )

    if use_delay == "no":
        return

    print_possible_delays()

    max_pairs = len(hosts) * (len(hosts) - 1)

    try:
        count = int(ask("How many random delay rules?", "1"))
    except ValueError:
        raise SystemExit("Delay count must be a number")

    if count < 1:
        return

    if count > max_pairs:
        raise SystemExit(f"Too many delays. Maximum possible is {max_pairs}")

    min_delay = int(ask("Minimum delay in ms", "50"))
    max_delay = int(ask("Maximum delay in ms", "1000"))

    if min_delay < 0 or max_delay < min_delay:
        raise SystemExit("Invalid delay range")

    possible_pairs = []

    for src in hosts:
        for dst in hosts:
            if src["simulated_ip"] == dst["simulated_ip"]:
                continue

            possible_pairs.append(
                (src["simulated_ip"], dst["simulated_ip"])
            )

    selected_pairs = random.sample(possible_pairs, count)

    print("\nRandom delays selected:")

    for src, dst in selected_pairs:
        delay_ms = random.randint(min_delay, max_delay)

        print(f"  {src} -> {dst} = {delay_ms}ms")

        run([
            "./set_delay.sh",
            "set",
            src,
            dst,
            str(delay_ms),
        ])


def stop_docker_topology():
    if Path("docker-compose.yml").exists():
        try:
            run(["docker", "compose", "down", "-v", "--remove-orphans"])
        except subprocess.CalledProcessError:
            print("[!] Docker cleanup failed, continuing file cleanup.")


def process_replay():
    pcap = Path(ask("Original PCAP to replay")).expanduser().resolve()

    label = ask_choice(
        "Label? benign(b) / malicious(m)",
        {"benign", "malicious"},
        {"b": "benign", "m": "malicious"},
    )

    clean_pcap = f"gateway_egress_{pcap.stem}_sim.pcap"
    labeled_csv = f"labeled_conn_{pcap.stem}_sim.csv"

    try:
        run(["python3", "extract_topology.py", pcap])

        run([
            "python3", "generate_compose.py",
            "--topology", "simulated_topology.json",
            "--pcap", "gateway.pcap",
            "--out", "docker-compose.yml",
        ])

        run(["docker", "compose", "up", "-d"])

        maybe_apply_delay()

        run([
            "python3", "replay_traffic.py",
            "--pcap", pcap,
            "--topology", "simulated_topology.json",
            "--ground-truth", GT,
            "--clean-out", clean_pcap,
            "--label", label,
        ])

        zeek_and_label(clean_pcap, labeled_csv)

        print(f"[+] Done replay -> {labeled_csv}")
        print(f"[+] Kept cleaned PCAP -> {clean_pcap}")

    finally:
        stop_docker_topology()
        cleanup_experiment_files()


def merge_only():
    run(["python3", "merge_datasets.py"])


def train_only():
    run(["python3", "train_xgboost.py"])


def merge_and_train():
    print("\n=== Create TRAIN dataset ===")
    merge_only()

    print("\n=== Create TEST dataset ===")
    merge_only()

    print("\n=== Train and evaluate model ===")
    train_only()


def main():
    print("Interactive PCAP -> Zeek labeled -> ML pipeline")
    print("Commands:")
    print("  base(b)    = label original PCAP directly")
    print("  replay(r)  = replay PCAP in simulated network")
    print("  merge(mg)  = create train or test dataset")
    print("  train(t)   = run ML using train_dataset.csv and test_dataset.csv")
    print("  both(bt)   = create both datasets then run ML")
    print("  quit(q)    = exit")

    while True:
        mode = ask_choice(
            "\nChoose action: base(b) / replay(r) / merge(mg) / train(t) / both(bt) / quit(q)",
            {"base", "replay", "merge", "train", "both", "quit"},
            {
                "b": "base",
                "r": "replay",
                "mg": "merge",
                "t": "train",
                "bt": "both",
                "q": "quit",
            },
        )

        if mode == "base":
            process_base()
        elif mode == "replay":
            process_replay()
        elif mode == "merge":
            merge_only()
        elif mode == "train":
            train_only()
        elif mode == "both":
            merge_and_train()
        elif mode == "quit":
            break

        again = ask_choice(
            "Do another action? yes(y) / no(n)",
            {"yes", "no"},
            {"y": "yes", "n": "no"},
        )

        if again == "no":
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(1)