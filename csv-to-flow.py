import pandas as pd
# Load labeled packets CSV
df = pd.read_csv("labeled_packets.csv")

# Parse timestamps as UTC datetime
df["timestamp_utc"] = pd.to_datetime(df["timestamp_utc"], utc=True)

# Sort by time for flow windowing 
df = df.sort_values("timestamp_utc").reset_index(drop=True)
df.head(5)

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

# Build a final flow_id (hashable string, easy to use later)
df["flow_id"] = df["flow_key"].astype(str) + "|s=" + df["session_id"].astype(str)

# Show a few packets with their session assignment
df[["timestamp_utc", "flow_key", "delta", "new_session", "session_id", "flow_id", "label"]].head(15)
