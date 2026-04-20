#!/usr/bin/env python3

import csv
import json
import sys
from datetime import datetime, timezone


def parse_utc(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def load_ground_truth(path: str):
    rows = []

    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            if row.get("status") != "completed":
                continue

            row["start_dt"] = parse_utc(row["replay_start_time_utc"])
            row["end_dt"] = parse_utc(row["replay_end_time_utc"])

            if not row.get("traffic_label"):
                row["traffic_label"] = "benign"

            rows.append(row)

    return rows


def zeek_ts_to_datetime(ts_value) -> datetime:
    return datetime.fromtimestamp(float(ts_value), tz=timezone.utc)


def label_record(rec: dict, gt_rows: list):
    ts = zeek_ts_to_datetime(rec["ts"])
    orig_h = rec.get("id.orig_h", "")

    for gt in gt_rows:
        sender_ip = gt.get("mapped_sender_ip", "")

        if not (gt["start_dt"] <= ts <= gt["end_dt"]):
            continue

        if orig_h == sender_ip:
            return {
                "label": gt.get("traffic_label", "malicious"),
                "attack_class": gt.get("attack_class", ""),
                "execution_id": gt.get("execution_id", ""),
                "sample_id": gt.get("sample_id", ""),
            }

    return {
        "label": "benign",
        "attack_class": "",
        "execution_id": "",
        "sample_id": "",
    }


def main():
    if len(sys.argv) != 4:
        print("Usage: python3 label_zeek.py <ground_truth.csv> <conn.log.json> <output.csv>")
        sys.exit(1)

    ground_truth_path = sys.argv[1]
    conn_log_path = sys.argv[2]
    output_path = sys.argv[3]

    gt_rows = load_ground_truth(ground_truth_path)
    output_rows = []
    all_fieldnames = []

    with open(conn_log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            rec = json.loads(line)
            if not isinstance(rec, dict) or "ts" not in rec:
                continue

            rec.update(label_record(rec, gt_rows))

            for key in rec.keys():
                if key not in all_fieldnames:
                    all_fieldnames.append(key)

            output_rows.append(rec)

    if not output_rows:
        print("No Zeek records found.")
        sys.exit(1)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"[+] Wrote labeled Zeek records to: {output_path}")


if __name__ == "__main__":
    main()