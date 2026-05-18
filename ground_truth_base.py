#!/usr/bin/env python3
import argparse
import csv
import subprocess
from pathlib import Path
from datetime import datetime, timezone

GT_FIELDS = [
    "execution_id", "sample_id", "traffic_label",
    "sender_containers", "sender_interfaces",
    "replay_start_time_utc", "replay_end_time_utc", "replay_multiplier",
    "status", "notes",
]


def run(cmd):
    return subprocess.run(cmd, text=True, capture_output=True, check=True).stdout.strip()


def utc_from_epoch(ts):
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def pcap_time_window(pcap):
    out = run([
        "tshark", "-r", str(pcap),
        "-T", "fields",
        "-e", "frame.time_epoch",
    ])

    times = [x.strip() for x in out.splitlines() if x.strip()]
    if not times:
        raise RuntimeError(f"No packets found in {pcap}")

    return utc_from_epoch(times[0]), utc_from_epoch(times[-1])


def read_existing(path):
    path = Path(path)
    if not path.exists():
        return []

    with path.open(newline="", encoding="utf-8") as f:
        return [{k: row.get(k, "") for k in GT_FIELDS} for row in csv.DictReader(f)]


def write_rows(path, rows):
    with Path(path).open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=GT_FIELDS)
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcaps", nargs="+", required=True)
    ap.add_argument("--label", required=True, choices=["benign", "malicious"])
    ap.add_argument("--ground-truth", default="ground_truth.csv")
    ap.add_argument("--notes", default="original_pcap")
    args = ap.parse_args()

    rows = read_existing(args.ground_truth)
    next_id = len(rows) + 1

    for p in args.pcaps:
        pcap = Path(p)
        start, end = pcap_time_window(pcap)

        rows.append({
            "execution_id": str(next_id),
            "sample_id": f"{pcap.stem}_base",
            "traffic_label": args.label,
            "replay_start_time_utc": start,
            "replay_end_time_utc": end,
            "replay_multiplier": "1.0",
            "status": "completed",
            "notes": "original_pcap",
        })

        print(f"[+] Added {pcap.name}: {args.label}, {start} -> {end}")
        next_id += 1

    write_rows(args.ground_truth, rows)
    print(f"[*] Ground truth updated: {args.ground_truth}")


if __name__ == "__main__":
    main()