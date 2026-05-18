#!/usr/bin/env python3
from pathlib import Path
import json
import subprocess
import sys

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

    run([
        "python3", "ground_truth_base.py",
        "--pcaps", pcap,
        "--label", label,
        "--ground-truth", GT,
    ])

    out_csv = f"labeled_conn_{pcap.stem}_base.csv"
    zeek_and_label(pcap, out_csv)

    print(f"[+] Done base -> {out_csv}")


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
    use_delay = ask_choice(
        "Apply gateway delay before replay? yes(y) / no(n)",
        {"yes", "no"},
        {"y": "yes", "n": "no"},
    )

    if use_delay == "no":
        return

    print_possible_delays()

    while True:
        src = ask("Delay source simulated IP")
        dst = ask("Delay destination simulated IP")
        ms = ask("Delay in milliseconds", "100")

        run(["./set_delay.sh", "set", src, dst, ms])

        more = ask_choice(
            "Add another delay rule? yes(y) / no(n)",
            {"yes", "no"},
            {"y": "yes", "n": "no"},
        )

        if more == "no":
            break

    run(["./set_delay.sh", "list"])


def process_replay():
    pcap = Path(ask("Original PCAP to replay")).expanduser().resolve()

    label = ask_choice(
        "Label? benign(b) / malicious(m)",
        {"benign", "malicious"},
        {"b": "benign", "m": "malicious"},
    )

    clean_pcap = f"gateway_egress_{pcap.stem}_sim.pcap"
    labeled_csv = f"labeled_conn_{pcap.stem}_sim.csv"

    run(["python3", "extract_topology.py", pcap])

    run([
        "python3", "generate_compose.py",
        "--topology", "simulated_topology.json",
        "--pcap", "gateway.pcap",
        "--out", "docker-compose.yml",
    ])

    run(["docker", "compose", "up", "-d"])

    try:
        maybe_apply_delay()

        replay_cmd = [
            "python3", "replay_traffic.py",
            "--pcap", pcap,
            "--topology", "simulated_topology.json",
            "--ground-truth", GT,
            "--clean-out", clean_pcap,
            "--label", label,
        ]

        run(replay_cmd)

        zeek_and_label(clean_pcap, labeled_csv)

        print(f"[+] Done replay -> {labeled_csv}")

    finally:
        down = ask_choice(
            "Stop Docker topology now? yes(y) / no(n)",
            {"yes", "no"},
            {"y": "yes", "n": "no"},
        )

        if down == "yes":
            run(["docker", "compose", "down", "-v", "--remove-orphans"])


def merge_only():
    run(["python3", "merge_datasets.py"])


def train_only():
    run(["python3", "train_xgboost.py"])


def merge_and_train():
    merge_only()
    train_only()


def main():
    print("Interactive PCAP -> Zeek labeled -> ML pipeline")
    print("Commands:")
    print("  base(b)    = label original PCAP directly")
    print("  replay(r)  = replay PCAP in simulated network")
    print("  merge(mg)  = merge labeled_conn_*.csv")
    print("  train(t)   = train ML on merged_dataset.csv")
    print("  both(bt)   = merge then train")
    print("  quit(q)    = exit")

    while True:
        mode = ask_choice(
            "\nWhat do you want to process? base(b) / replay(r) / merge(mg) / train(t) / both(bt) / quit(q)",
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
            finish = ask_choice(
                "Merge labeled Zeek files and train ML now? yes(y) / no(n)",
                {"yes", "no"},
                {"y": "yes", "n": "no"},
            )

            if finish == "yes":
                merge_and_train()

            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(1)