# Malicious Traffic Generator for ML-Based Network Anomaly Detection

Master's Thesis (30 hp)  
Chalmers University of Technology – Gothenburg, Sweden  
Department of Computer Science and Engineering (CSE)  
Secura Lab, NS Unit, CNS Division  

Student: Mohammad Mourad  
Supervisors: Muoi Tran and Ilias Chanis  
Examiner: Yinan Yu

## Overview

This repository contains a Docker-based framework for generating, replaying, capturing, labeling, and evaluating network traffic for ML-based network anomaly detection research.

The current workflow is based on replaying traffic from existing PCAP files inside a controlled simulated network. The framework extracts the topology from an original PCAP, maps original hosts to isolated Docker zones, replays packets through a routed gateway, captures the replayed traffic, creates ground-truth metadata, converts traffic to Zeek flows, labels those flows, and optionally trains a simple ML baseline.

The framework is designed for controlled research experiments. It does not require live malware execution during replay. Malware or benign samples can first be executed in a sandbox or isolated environment, and the resulting PCAP can then be replayed safely inside the simulated Docker testbed.

## Main Features

- Extracts host mappings, communication edges, DNS names, and DHCP metadata from an input PCAP.
- Builds a simulated topology using Docker networks and a central routed gateway.
- Maps internal private hosts to Zone A and external hosts to separate zones.
- Ignores broadcast and multicast hosts as Docker containers, while still handling replay-relevant discovery traffic.
- Supports DHCP `0.0.0.0` ownership metadata for replay.
- Rewrites and replays packets with Scapy inside Docker containers.
- Captures replayed traffic at the gateway.
- Can clean gateway captures to keep expected replay traffic.
- Generates and updates `ground_truth.csv` automatically for replayed PCAPs.
- Can add ground-truth rows directly from original PCAP time windows.
- Uses Zeek `conn.log` JSON output for flow extraction.
- Labels Zeek flows using ground-truth replay or original-PCAP time windows.
- Maps packets back to labeled Zeek flows.
- Merges labeled datasets and trains a simple XGBoost baseline.
- Supports gateway-based per-source/destination delay using Linux `tc` and `netem`.

## Repository Files

| File | Purpose |
|---|---|
| `extract_topology.py` | Reads an input PCAP with `tshark`, extracts hosts, edges, DNS names, DHCP metadata, and writes `topology.json` and `simulated_topology.json`. |
| `generate_compose.py` | Builds `docker-compose.yml` from `simulated_topology.json`. |
| `replay_traffic.py` | Rewrites the original PCAP into the simulated topology, replays it, captures gateway traffic, cleans captures, and appends replay metadata to `ground_truth.csv`. |
| `ground_truth_base.py` | Adds ground-truth rows for original PCAPs without replaying them. |
| `label_zeek.py` | Labels Zeek `conn.log` JSON records using `ground_truth.csv`. |
| `map_packets_to_flows.py` | Maps packets from a PCAP to labeled Zeek flows. |
| `merge_datasets.py` | Merges all `labeled_conn_*.csv` files into `merged_dataset.csv`. |
| `train_xgboost.py` | Trains a simple binary XGBoost baseline on `merged_dataset.csv`. |
| `run_pipeline.py` | Interactive end-to-end pipeline for base labelling, replay, optional delay setup, Zeek labelling, dataset merging, and ML training. |
| `set_delay.sh` | Adds, removes, or lists gateway delay rules between two simulated IPs. |
| `ground_truth.csv` | Current ground-truth metadata file. |
| `README.md` | Project usage documentation. |

## Requirements

Recommended environment:

- Linux or WSL2 with Docker support
- Python 3.9+
- Docker and Docker Compose
- `tshark`
- `tcpdump`
- Zeek
- Python packages:
  - `pandas`
  - `scapy`
  - `PyYAML`
  - `scikit-learn`
  - `xgboost`

Install Python dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install pandas scapy PyYAML scikit-learn xgboost
```

Check system tools:

```bash
docker --version
docker compose version
tshark --version
tcpdump --version
zeek --version
```

## Typical Workflow

The normal pipeline is:

```text
original PCAP
  -> extract topology
  -> generate Docker Compose testbed
  -> start containers
  -> optionally configure delay
  -> replay PCAP
  -> run Zeek on captured/cleaned PCAP
  -> label Zeek flows
  -> optionally map packets to flows
  -> merge datasets
  -> train ML baseline
```
## Interactive Pipeline

Instead of running every script manually, `run_pipeline.py` provides an interactive workflow for the full PCAP-to-ML pipeline.

Run:

```bash
python3 run_pipeline.py
```

## 1. Extract Topology from a PCAP

Run:

```bash
python3 extract_topology.py <input.pcap>
```

Example:

```bash
python3 extract_topology.py 57627_dump.pcap
```

Outputs:

- `topology.json`
- `simulated_topology.json`

`simulated_topology.json` contains the mapping from original IP addresses to simulated Docker IP addresses. Internal private IPs are mapped to Zone A. External hosts are mapped to separate external zones.

## 2. Generate Docker Compose

Run:

```bash
python3 generate_compose.py \
  --topology simulated_topology.json \
  --pcap gateway.pcap \
  --out docker-compose.yml
```

The generated compose file contains:

- one gateway container: `master-thesis-gw`
- one Docker network per simulated host
- one host container per active mapped host
- one route helper container per host
- an optional capture service under the `capture` profile

Start the simulated network:

```bash
docker compose up -d
```

Stop and remove it:

```bash
docker compose down -v --remove-orphans
```

## 3. Optional: Capture Manually at the Gateway

The generated compose file includes a capture profile:

```bash
docker compose --profile capture up -d capture
```

Stop capture:

```bash
docker compose stop capture
```

This writes the configured capture file, for example `gateway.pcap`.

In most replay experiments, `replay_traffic.py` starts its own gateway captures automatically, so the manual capture profile is optional.

## 4. Optional: Add Gateway Delay

Add delay from one simulated source IP to one simulated destination IP:

```bash
./set_delay.sh set <SRC_IP> <DST_IP> <DELAY_MS>
```

Example:

```bash
./set_delay.sh set 172.30.11.11 172.31.11.11 100
```

Remove delay:

```bash
./set_delay.sh del <SRC_IP> <DST_IP>
```

List delay rules:

```bash
./set_delay.sh list
```

Delay rules are applied on the gateway egress interface selected by the route to the destination IP.

## 5. Replay Traffic

Run:

```bash
python3 replay_traffic.py \
  --pcap <input.pcap> \
  --topology simulated_topology.json \
  --multiplier 1.0 \
  --attack-class "malware traffic"
```

Example benign replay:

```bash
python3 replay_traffic.py \
  --pcap benign_sample.pcap \
  --topology simulated_topology.json \
  --multiplier 1.0
```

Example malicious replay:

```bash
python3 replay_traffic.py \
  --pcap malware_sample.pcap \
  --topology simulated_topology.json \
  --multiplier 1.0 \
  --attack-class "malware traffic"
```

Important arguments:

| Argument | Meaning |
|---|---|
| `--pcap` | Original PCAP to replay. If omitted, the script uses the `pcap_file` field from `simulated_topology.json`. |
| `--topology` | Topology mapping file. Default: `simulated_topology.json`. |
| `--multiplier` | Timing multiplier for replay speed. Default: `1.0`. |
| `--ground-truth` | Ground-truth CSV path. Default: `ground_truth.csv`. |
| `--attack-class` | If provided, the replay is labeled malicious. If empty, it is labeled benign. |
| `--notes` | Extra notes written to ground truth. |
| `--capture-out` | Raw gateway any-interface capture. Default: `gateway_capture_any.pcap`. |
| `--clean-out` | Cleaned gateway egress capture. Default: `gateway_egress.pcap`. |
| `--keep-unmapped` | Keep packets with unmapped destinations when possible. |
| `--allow-missing-fallback` | Keep expected packets if some are missing from the filtered capture. |
| `--no-filter` | Skip capture cleaning. |
| `--post-capture-wait` | Seconds to wait before stopping capture. Default: `2.0`. |

Outputs commonly include:

- `gateway_capture_any.pcap`
- `gateway_egress.pcap`
- `gateway_iface_<iface>.pcap`
- updated `ground_truth.csv`

## 6. Ground Truth

Current ground-truth columns:

```csv
execution_id,sample_id,attack_class,traffic_label,replay_start_time_utc,replay_end_time_utc,replay_multiplier,status,notes
```

Meaning:

| Column | Meaning |
|---|---|
| `execution_id` | Sequential experiment row ID. |
| `sample_id` | Sample name, usually based on the PCAP filename. Replayed samples are versioned automatically. |
| `traffic_label` | `benign` or `malicious`. |
| `replay_start_time_utc` | UTC start time used for labeling. |
| `replay_end_time_utc` | UTC end time used for labeling. |
| `replay_multiplier` | Replay timing multiplier. |
| `status` | Usually `completed` or `failed`. |
| `notes` | Optional experiment notes or error information. |

### Add Ground Truth for Original PCAPs

Use this when you want to label original PCAPs directly without replaying them:

```bash
python3 ground_truth_base.py \
  --pcaps <pcap1> <pcap2> \
  --label benign \
  --ground-truth ground_truth.csv
```

For malicious original PCAPs:

```bash
python3 ground_truth_base.py \
  --pcaps malware_sample.pcap \
  --label malicious \
  --attack-class "malware traffic" \
  --ground-truth ground_truth.csv
```

The script reads the first and last packet timestamps using `tshark` and appends the corresponding time window to `ground_truth.csv`. The `sample_id` format is `<pcap_stem>_base`.

## 7. Convert PCAP to Zeek Flows

Run Zeek on a captured or cleaned PCAP:

```bash
zeek -b -C -r gateway_egress.pcap base/protocols/conn LogAscii::use_json=T
```

This creates `conn.log` in JSON format.

If you want to keep outputs organized, run Zeek in a separate directory:

```bash
mkdir -p zeek_out
cd zeek_out
zeek -b -C -r ../gateway_egress.pcap base/protocols/conn LogAscii::use_json=T
cd ..
```

## 8. Label Zeek Flows

Run:

```bash
python3 label_zeek.py ground_truth.csv conn.log labeled_conn.csv
```

Example if Zeek output is in a directory:

```bash
python3 label_zeek.py ground_truth.csv zeek_out/conn.log labeled_conn_sample.csv
```

Labeling logic:

- only ground-truth rows with `status=completed` are used
- Zeek flow start/end time is compared with each ground-truth time window
- any overlapping flow receives the ground-truth label
- flows with no overlap are labeled `benign`

## 9. Map Packets to Labeled Flows

Run:

```bash
python3 map_packets_to_flows.py \
  --pcap gateway_egress.pcap \
  --flows labeled_conn_sample.csv \
  --out packet_flow_map.csv
```

Optional arguments:

```bash
python3 map_packets_to_flows.py \
  --pcap gateway_egress.pcap \
  --flows labeled_conn_sample.csv \
  --out packet_flow_map.csv \
  --time-slack 1.0 \
  --all-candidates
```

This creates a packet-level mapping to Zeek flow rows, labels, attack classes, and sample IDs.

## 10. Merge Datasets

`merge_datasets.py` reads all files matching:

```text
labeled_conn_*.csv
```

Run:

```bash
python3 merge_datasets.py
```

Output:

```text
merged_dataset.csv
```

The script also adds a `source_file` column for debugging.

## 11. Train a Simple ML Baseline

Run:

```bash
python3 train_xgboost.py
```

The script expects:

```text
merged_dataset.csv
```

It trains a binary XGBoost classifier where:

- `benign` becomes class `0`
- any non-benign label becomes class `1`

Current numeric features:

```text
duration
orig_bytes
resp_bytes
orig_pkts
orig_ip_bytes
resp_pkts
resp_ip_bytes
missed_bytes
ip_proto
```

The output is a scikit-learn classification report.

## Full Example

```bash
# 1. Extract topology
python3 extract_topology.py sample.pcap

# 2. Generate Docker Compose
python3 generate_compose.py \
  --topology simulated_topology.json \
  --pcap gateway.pcap \
  --out docker-compose.yml

# 3. Start topology
docker compose up -d

# 4. Replay traffic and update ground truth
python3 replay_traffic.py \
  --pcap sample.pcap \
  --topology simulated_topology.json \
  --multiplier 1.0 \
  --attack-class "malware traffic" \
  --clean-out gateway_egress.pcap

# 5. Convert to Zeek flows
zeek -b -C -r gateway_egress.pcap base/protocols/conn LogAscii::use_json=T

# 6. Label Zeek flows
python3 label_zeek.py ground_truth.csv conn.log labeled_conn_sample.csv

# 7. Optional packet-to-flow mapping
python3 map_packets_to_flows.py \
  --pcap gateway_egress.pcap \
  --flows labeled_conn_sample.csv \
  --out packet_flow_map_sample.csv

# 8. Stop topology
docker compose down -v --remove-orphans
```

## Notes on Topology Mapping

- Private IP addresses are treated as internal hosts.
- Internal hosts are placed in Zone A using `172.30.x.x` addressing.
- External hosts are placed in separate external zones starting from `172.31.x.x`.
- Broadcast and multicast hosts are ignored as containers but may still be handled during replay.
- DHCP `0.0.0.0` is metadata only and is assigned to an inferred internal owner when possible.
- The gateway is created as `master-thesis-gw` and routes traffic between all simulated networks.

## Notes on Replay

`replay_traffic.py` performs several replay-specific transformations:

- rewrites original IP addresses to simulated IP addresses
- rewrites ARP protocol addresses
- recalculates checksums and lengths
- pads Ethernet frames when needed
- normalizes TCP sequence and ACK values
- suppresses local TCP RST and ICMP unreachable noise
- captures gateway egress traffic
- filters captured packets against expected replay packets unless `--no-filter` is used

## Safety and Ethics

Use this framework only in isolated research environments. Do not run unknown malware on a normal host network. Recommended practice is:

1. Execute malware or suspicious binaries only inside a sandbox or isolated VM.
2. Export the resulting PCAP.
3. Replay the PCAP inside this Docker-based simulated testbed.
4. Keep the Docker testbed disconnected from production networks.

## Troubleshooting

### `tshark` not found

Install Wireshark command-line tools:

```bash
sudo apt install tshark
```

### Zeek does not produce JSON

Make sure the command includes:

```bash
LogAscii::use_json=T
```

### Gateway is not running

Start the generated topology first:

```bash
docker compose up -d
```

### Delay script says source or destination IP does not exist

Check the simulated IPs in `simulated_topology.json` and make sure the Docker topology is running.

### No labeled malicious flows

Check:

- `ground_truth.csv` uses `status=completed`
- `attack_class` is set for malicious traffic
- Zeek flow timestamps overlap `replay_start_time_utc` and `replay_end_time_utc`
- the correct `conn.log` and PCAP are being used

## Current Status

The project has moved from a simple hand-written Docker setup and packet-labeling prototype to a topology-driven replay framework. The current implementation focuses on:

- extracting topology from original PCAPs
- generating simulated Docker networks automatically
- replaying PCAP traffic through a gateway
- capturing and cleaning gateway traffic
- producing ground truth for replayed and original PCAPs
- labeling Zeek flows
- preparing flow-level datasets for ML evaluation

## License

This project is licensed under the MIT License. See the LICENSE file for details.