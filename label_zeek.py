#!/usr/bin/env python3

import csv
import json
import sys
from datetime import datetime, timezone


# ------------------------------------------------------------
# Convert a UTC timestamp string from ground truth into
# a Python datetime object.
#
# Example:
# 2026-03-14T11:57:32Z
# ------------------------------------------------------------
def parse_utc(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ------------------------------------------------------------
# Load the ground truth CSV file.
#
# Only rows with status="completed" are used for labeling.
# For each valid row, convert start and end timestamps into
# datetime objects so time comparison is easy later.
# ------------------------------------------------------------
def load_ground_truth(path: str):
    rows = []

    with open(path, "r", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            # Ignore runs that did not complete successfully
            if row["status"] != "completed":
                continue

            # Convert times from strings to datetime objects
            row["start_dt"] = parse_utc(row["start_time_utc"])
            row["end_dt"] = parse_utc(row["end_time_utc"])

            rows.append(row)

    return rows


# ------------------------------------------------------------
# Convert Zeek timestamp (Unix time) into datetime.
#
# Example Zeek timestamp:
# 1773489461.018197
# ------------------------------------------------------------
def zeek_ts_to_datetime(ts_value) -> datetime:
    return datetime.fromtimestamp(float(ts_value), tz=timezone.utc)


# ------------------------------------------------------------
# Label a single Zeek connection record.
#
# A Zeek record is labeled malicious if:
#   1) its timestamp is inside a malware execution window
#   2) either source IP or destination IP matches the container IP
#
# Otherwise it is labeled benign.
# ------------------------------------------------------------
def label_record(rec: dict, gt_rows: list):
    # Convert Zeek timestamp to datetime
    ts = zeek_ts_to_datetime(rec["ts"])

    # Zeek source and destination IPs
    orig_h = rec.get("id.orig_h", "")
    resp_h = rec.get("id.resp_h", "")

    # Compare this Zeek record against every completed execution
    for gt in gt_rows:
        gt_ip = gt["container_ip"]

        # Check whether Zeek record happened during this execution window
        if not (gt["start_dt"] <= ts <= gt["end_dt"]):
            continue

        # Check whether this connection involves the malware container
        if orig_h == gt_ip or resp_h == gt_ip:
            return {
                "label": "malicious",
                "class": gt["class"],
                "execution_id": gt["execution_id"],
                "sample_id": gt["sample_id"],
            }

    # No match found -> benign
    return {
        "label": "benign",
        "class": "",
        "execution_id": "",
        "sample_id": "",
    }


# ------------------------------------------------------------
# Main program
# ------------------------------------------------------------
def main():
    # Expect exactly 3 arguments after script name
    if len(sys.argv) != 4:
        print("Usage: python3 label_zeek.py <ground_truth.csv> <conn.log.json> <output.csv>")
        sys.exit(1)

    ground_truth_path = sys.argv[1]
    conn_log_path = sys.argv[2]
    output_path = sys.argv[3]

    # Load malware execution windows
    gt_rows = load_ground_truth(ground_truth_path)

    # Store labeled Zeek records
    output_rows = []

    # Store every field name seen across all records
    # This avoids crashing when some Zeek rows have extra fields
    all_fieldnames = []

    with open(conn_log_path, "r") as f:
        for line in f:
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Convert JSON line to Python dictionary
            rec = json.loads(line)

            # Skip invalid lines
            if not isinstance(rec, dict) or "ts" not in rec:
                continue

            # Add malicious/benign labels
            labels = label_record(rec, gt_rows)
            rec.update(labels)

            # Build a union of all keys from all Zeek records
            for key in rec.keys():
                if key not in all_fieldnames:
                    all_fieldnames.append(key)

            output_rows.append(rec)

    # Stop if no valid Zeek records were found
    if not output_rows:
        print("No Zeek records found.")
        sys.exit(1)

    # Write labeled output CSV
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=all_fieldnames,
            extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"[+] Wrote labeled Zeek records to: {output_path}")


# ------------------------------------------------------------
# Entry point
# ------------------------------------------------------------
if __name__ == "__main__":
    main()