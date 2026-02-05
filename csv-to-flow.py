import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
# Load labeled packets CSV
df = pd.read_csv("labeled_packets.csv")

# Parse timestamps as UTC datetime
df["timestamp_utc"] = pd.to_datetime(df["timestamp_utc"], utc=True)

# unidirectional flow direction
df["direction"] = df["src_ip"].astype(str) + "->" + df["dst_ip"].astype(str)

# Port dtypes, ICMP has no ports
df["src_port"] = df["src_port"].fillna(-1).astype(int)
df["dst_port"] = df["dst_port"].fillna(-1).astype(int)

# Sort by time for flow windowing 
df = df.sort_values("timestamp_utc").reset_index(drop=True)


def make_flow_key(row):
    if row["protocol"].lower() == "icmp":
        # ICMP has no ports
        return (
            row["src_ip"],
            row["dst_ip"],
            row["protocol"]
        )
    else:
        return (
            row["src_ip"],
            row["dst_ip"],
            row["src_port"],
            row["dst_port"],
            row["protocol"]
        )

# Apply flow key creation
df["flow_key"] = df.apply(make_flow_key, axis=1)
df[["timestamp_utc", "flow_key"]].head(5)


IDLE_TIMEOUT = pd.Timedelta(seconds=2)

# Ensure sorted by flow_key then time 
df = df.sort_values(["flow_key", "timestamp_utc"]).reset_index(drop=True)

# Time since previous packet within same flow_key
df["delta"] = df.groupby("flow_key")["timestamp_utc"].diff()

# New session starts if:
#  - first packet in that key (delta is NaT)
#  - OR gap > idle timeout
df["new_session"] = df["delta"].isna() | (df["delta"] > IDLE_TIMEOUT)

# Session index per flow_key
df["session_id"] = df.groupby("flow_key")["new_session"].cumsum()

# Build a final flow_id, hashable string
df["flow_id"] = df["flow_key"].astype(str) + "|s=" + df["session_id"].astype(str)

# Show a few packets with their session assignment
df[["timestamp_utc", "flow_key", "delta", "new_session", "session_id", "flow_id", "label"]].head(15)




def flow_label(series):
    return series.value_counts().idxmax()

flows = (
    df.groupby("flow_id")
      .agg(
          flow_start=("timestamp_utc", "min"),
          flow_end=("timestamp_utc", "max"),
          packets=("timestamp_utc", "count"),
          mean_iat_s=("delta", lambda s: s.dropna().dt.total_seconds().mean() if s.notna().any() else 0.0),
          std_iat_s=("delta",  lambda s: s.dropna().dt.total_seconds().std(ddof=0) if s.notna().any() else 0.0),
          label=("label", flow_label),
          protocol=("protocol", "first"),
          src_ip=("src_ip", "first"),
          dst_ip=("dst_ip", "first"),
          src_port=("src_port", "first"),
          dst_port=("dst_port", "first"),
      )
      .reset_index()
)

# Duration in seconds
flows["duration_s"] = (flows["flow_end"] - flows["flow_start"]).dt.total_seconds()

# 1) Encode protocol as numeric
protocol_map = {"tcp": 0, "udp": 1, "icmp": 2}
flows["protocol_id"] = flows["protocol"].str.lower().map(protocol_map)

# Safety check: ensure no unknown protocols slipped in
unknown = flows["protocol_id"].isna().sum()
print("\nUnknown protocols: ", unknown)
if unknown > 0:
    print("Unknown protocol values:", flows.loc[flows["protocol_id"].isna(), "protocol"].unique())

# 2) Ensure ports are integers (should already be, but keep it safe)
flows["src_port"] = flows["src_port"].fillna(-1).astype(int)
flows["dst_port"] = flows["dst_port"].fillna(-1).astype(int)

# 3) Save full flows table (for analysis/debugging/thesis tables)
flows.to_csv("flows_full.csv", index=False)

# 4) Select ML features (keep it simple + numeric)
feature_cols = [
    "duration_s",
    "packets",
    "mean_iat_s",
    "std_iat_s",
    "src_port",
    "dst_port",
    "protocol_id",
]

ml = flows[feature_cols + ["label"]].copy()

# 5) Save ML dataset
ml.to_csv("flows_ml.csv", index=False)

# Load ML-ready flows
ml = pd.read_csv("flows_ml.csv")

X = ml.drop(columns=["label"])
y = ml["label"]

# Train / test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.3,
    random_state=42,
    stratify=y
)

# Baseline model
clf = LogisticRegression(max_iter=1000)
clf.fit(X_train, y_train)

# Predictions
y_pred = clf.predict(X_test)

print("\nConfusion matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification report:")
print(classification_report(y_test, y_pred))


