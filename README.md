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
docker compose down
```

## Enter Attacker Container

```bash
docker exec -it master-thesis-attacker bash
```

## Example Attacks

From the attacker container, run attacks against the server:

```bash
# ICMP ping attack
ping -c 5 server

# Port scanning attack
nmap -p 1-1000 server
```

## Label PCAP Packets

Set up Python environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pandas dpkt python-dateutil
```

Run the labeling script:

```bash
python label_pcap.py \
  --pcap pcaps/server_capture.pcap \
  --ground-truth ground_truth.csv \
  --out labeled_packets.csv
```