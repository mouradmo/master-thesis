# Malicious Traffic Generator for ML-Based Network Anomaly Detection

Master's Thesis (30 hp)  
Chalmers University of Technology – Gothenburg, Sweden  
Department of Computer Science and Engineering (CSE)  
Secura Lab, NS Unit, CNS Division  

## Overview
This repository contains the research framework developed as part of the
master's thesis *"Malicious Traffic Generator for ML-Based Network Anomaly
Detection"*.

The framework enables controlled generation of **synthetic, labeled malicious
network traffic** for evaluating ML-based anomaly detection systems, while
maintaining strong ethical and security constraints.

## Requirements
- Python ≥ 3.9
- Docker & Docker Compose
- Linux-based environment (recommended)
- Virtual or containerized testbed (e.g., isolated VMs or containers)

## Installation
Clone the repository and move into the project directory:

```bash
git clone https://github.com/mouradmo/master-thesis
cd master-thesis
```

## Verify Installation

```bash
docker --version
docker compose version
```

## Start and Stop Docker Compose

```bash
# Start all services
docker compose up -d

# Stop all services
docker compose down -v --remove-orphans
```

## Enter container

```bash
docker exec -it master-thesis-container sh
```



## Label PCAP Packets

Set up Python environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
```

Run the labeling script:

```bash
python label_pcap.py \
  --pcap path_to_pcap \
  --ground-truth ground_truth.csv \
  --out labeled_packets.csv
```

Run csv_to_flow
```bash
csv-to-flow.py input_csv  output_flow
``` 
Run generate-compose.py

```bash
python3 generate_compose.py --topology simulated_topology.json --out docker-compose.yml
python3 generate_compose.py --zones x --hosts-per-zone y,z --pcap gateway.pcap

```

Run set_delay.sh

```bash
./set_delay.sh set <src_ip> <dst_ip> <delay_ms>

./set_delay.sh del <src_ip> <dst_ip>

./set_delay.sh list

```

```bash
zeek -b -C -r gateway.pcap base/protocols/conn LogAscii::use_json=T
```

Running Zeek label file
```bash
python3 label_zeek.py ground_truth.csv conn.log labeled_conn.csv
```

Start/stop gateway capture in interface any
```bash
docker compose --profile capture up -d
docker compose stop capture
```

Extract topology
```bash
python3 extract_topology.py 57627_dump.pcap
```

Run replay traffic
```bash
python3 replay_traffic.py --pcap 57627_dump.pcap --multiplier 1.0 --attack_class name
```

 docker exec -it master-thesis-gw sh -lc 'ls -l /tmp/replay_delay_rules && cat /tmp/replay_delay_rules/*'