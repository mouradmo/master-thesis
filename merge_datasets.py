#!/usr/bin/env python3

from pathlib import Path
import pandas as pd

# Find all labeled Zeek CSV files
files = sorted(Path(".").glob("labeled_conn_*.csv"))

if not files:
    raise SystemExit("No labeled_conn CSV files found")

dfs = []

for f in files:
    print(f"Loading {f}")
    df = pd.read_csv(f)

    # Keep source filename for debugging
    df["source_file"] = f.name

    dfs.append(df)

# Merge everything
merged = pd.concat(dfs, ignore_index=True)

print("\nMerged dataset shape:")
print(merged.shape)

print("\nLabels:")
print(merged["label"].value_counts(dropna=False))

# Save merged dataset
out = "merged_dataset.csv"
merged.to_csv(out, index=False)

print(f"\nSaved -> {out}")