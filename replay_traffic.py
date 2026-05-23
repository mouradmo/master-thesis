#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

from scapy.all import ARP, DNS, Ether, ICMP, IP, TCP, UDP, rdpcap, sendp, wrpcap
from scapy.packet import Padding

PREFIX = "master-thesis-"
GW = f"{PREFIX}gw"
SCAPY_IMAGE = "local/scapy-replay"

BCAST = "ff:ff:ff:ff:ff:ff"
ZERO = "00:00:00:00:00:00"
ANY_TMP = "/tmp/replay_gateway_any.pcap"
ANY_LOG = "/tmp/replay_gateway_any.log"
IFACE_TMP = "/tmp/replay_gateway_iface_"
IFACE_LOG = "/tmp/replay_gateway_iface_"
BAD_TYPES = {"ignore", "gateway", "dhcp_zero"}

# Ethernet destinations for common IPv4 discovery protocols.
PROTO_MAC = {
    137: BCAST,
    5353: "01:00:5e:00:00:fb",
    5355: "01:00:5e:00:00:fc",
    1900: "01:00:5e:7f:ff:fa",
}

# Ground-truth CSV columns.
GT_FIELDS = [
    "execution_id",
    "sample_id",
    "traffic_label",
    "replay_start_time_utc",
    "replay_end_time_utc",
    "replay_multiplier",
    "status",
    "notes",
]


def run(cmd, **kw):
    return subprocess.run([str(x) for x in cmd], text=True, capture_output=True, check=True, **kw)


def sh(container: str, cmd: str) -> str:
    return run(["docker", "exec", container, "sh", "-lc", cmd]).stdout.strip()


def now() -> datetime:
    return datetime.now(timezone.utc)


def utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: str | Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def ensure_image() -> None:
    # Build the Scapy replay image if it does not already exist.
    if subprocess.run(["docker", "image", "inspect", SCAPY_IMAGE], capture_output=True).returncode == 0:
        return

    with tempfile.TemporaryDirectory() as d:
        Path(d, "Dockerfile").write_text(
            "FROM python:3.12-slim\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends "
            "iproute2 tcpdump libpcap0.8 iptables && pip install --no-cache-dir scapy "
            "&& rm -rf /var/lib/apt/lists/*\n"
            'ENTRYPOINT ["python3"]\n',
            encoding="utf-8",
        )
        subprocess.run(["docker", "build", "-t", SCAPY_IMAGE, d], check=True)


def active_rows(topo):
    # Keep only topology rows that represent real replay containers.
    return [
        r for r in topo.get("mapping", [])
        if r.get("original_ip")
        and r.get("simulated_ip")
        and r.get("service_name")
        and r.get("gateway_ip")
        and r.get("sim_type") not in BAD_TYPES
        and r.get("simulated_ip") != "0.0.0.0"
    ]


def by_key(topo, key):
    return {r[key]: r for r in active_rows(topo)}


def dhcp_owner(topo):
    # Find which simulated host should emit DHCP packets with source 0.0.0.0.
    services = by_key(topo, "service_name")
    for r in topo.get("mapping", []):
        if r.get("sim_type") == "dhcp_zero" or r.get("original_ip") == "0.0.0.0":
            if r.get("service_name") in services:
                return services[r["service_name"]]

    internals = [r for r in active_rows(topo) if r.get("sim_type") == "internal"]
    return min(internals, key=lambda r: r["service_name"], default=None)


def ipmap(topo):
    # Map original IP addresses to simulated IP addresses.
    return {**{r["original_ip"]: r["simulated_ip"] for r in active_rows(topo)}, "0.0.0.0": "0.0.0.0"}


def route_iface(container, ip):
    return sh(container, f"ip route get {ip} | awk '{{for(i=1;i<=NF;i++) if($i==\"dev\"){{print $(i+1); exit}}}}'")


def safe_route_iface(container, *ips):
    for ip in filter(None, ips):
        try:
            if iface := route_iface(container, ip):
                return iface
        except Exception:
            pass
    return ""


def container_iface(container, gateway_ip):
    # Discover the interface used by a container to reach its gateway.
    for c in (f"{container}-route", container):
        if iface := safe_route_iface(c, gateway_ip):
            return iface
    raise RuntimeError(f"Could not discover interface for {container} towards {gateway_ip}")


def iface_mac(container, iface):
    if mac := sh(container, f"cat /sys/class/net/{iface}/address"):
        return mac.lower()
    raise RuntimeError(f"Could not read MAC for {container}:{iface}")


def is_bcast(ip):
    return ip == "255.255.255.255" or ip.endswith(".255")


def is_mcast(ip):
    try:
        return ip_address(ip).is_multicast
    except Exception:
        return False


def mcast_mac(ip):
    # Convert IPv4 multicast address to Ethernet multicast MAC.
    low23 = int(ip_address(ip)) & 0x7FFFFF
    return f"01:00:5e:{(low23 >> 16) & 0x7F:02x}:{(low23 >> 8) & 0xFF:02x}:{low23 & 0xFF:02x}"


def mapped_bcast(old_src, old_dst, m):
    # Map subnet broadcast to the simulated source subnet.
    src = m.get(old_src)
    return old_dst if old_dst == "255.255.255.255" or not src or src == "0.0.0.0" else ".".join(src.split(".")[:3] + ["255"])


def has(pkt, *layers):
    return all(layer in pkt for layer in layers)


def is_dhcp(pkt):
    return has(pkt, IP, UDP) and {int(pkt[UDP].sport), int(pkt[UDP].dport)} == {67, 68}


def replayable(pkt):
    return ARP in pkt or IP in pkt


def tcp(pkt):
    return has(pkt, IP, TCP)


def udp(pkt):
    return has(pkt, IP, UDP)


def eth(pkt):
    # Ensure the packet has an Ethernet header.
    q = pkt.copy()
    if Ether not in q:
        q = Ether(type=0x0806 if ARP in q else 0x0800) / q
    q[Ether].type = 0x0806 if ARP in q else 0x0800 if IP in q else q[Ether].type
    return q


def fix(pkt):
    # Remove checksums/lengths so Scapy recalculates them after rewriting.
    if IP in pkt:
        for f in ("len", "chksum"):
            if hasattr(pkt[IP], f):
                delattr(pkt[IP], f)
    for layer in (TCP, UDP, ICMP):
        if layer in pkt and hasattr(pkt[layer], "chksum"):
            del pkt[layer].chksum
    return pkt


def pad_eth_min(pkt):
    # Ethernet frames must be at least 60 bytes before FCS.
    q = eth(pkt)
    missing = 60 - len(bytes(q))
    return q / Padding(b"\x00" * missing) if missing > 0 else q


def payload_hash(pkt):
    # Used to match expected packets with captured packets.
    for layer in (UDP, TCP, ICMP, ARP):
        if layer in pkt:
            data = pkt[layer] if layer == ARP else pkt[layer].payload
            return hashlib.sha1(bytes(data)).hexdigest()
    return hashlib.sha1(bytes(pkt)).hexdigest()


def sender_ip(pkt, topo):
    # Identify which original host should send this packet.
    rows = by_key(topo, "original_ip")
    owner = None

    if IP in pkt:
        if pkt[IP].src == "0.0.0.0" and is_dhcp(pkt):
            owner = dhcp_owner(topo)
            return owner and owner["original_ip"]
        return pkt[IP].src if pkt[IP].src in rows else None

    if ARP in pkt:
        psrc, pdst = pkt[ARP].psrc, pkt[ARP].pdst
        if psrc in rows:
            return psrc
        if psrc == "0.0.0.0" and pdst in rows:
            return pdst
        owner = dhcp_owner(topo)
        return owner and owner["original_ip"]

    return None


def rewrite_ip(pkt, m, keep_unmapped=False):
    # Rewrite IP source/destination into the simulated topology.
    if IP not in pkt:
        return None

    old_src, old_dst = pkt[IP].src, pkt[IP].dst
    special_dst = is_bcast(old_dst) or is_mcast(old_dst)

    if old_src not in m or (old_dst not in m and not special_dst and not keep_unmapped):
        return None

    q = eth(pkt)
    q[IP].src = m.get(old_src, old_src)
    q[IP].dst = m[old_dst] if old_dst in m else mapped_bcast(old_src, old_dst, m) if old_dst.endswith(".255") else old_dst
    q.time = pkt.time
    return fix(q)


def rewrite_arp(pkt, m):
    # Rewrite ARP protocol addresses into the simulated topology.
    if ARP not in pkt:
        return None

    q = eth(pkt)
    if q[ARP].psrc in m:
        q[ARP].psrc = m[q[ARP].psrc]
    elif q[ARP].psrc == "0.0.0.0":
        q[ARP].psrc = "0.0.0.0"

    if q[ARP].pdst in m:
        q[ARP].pdst = m[q[ARP].pdst]
    elif q[ARP].pdst.endswith(".255"):
        q[ARP].pdst = mapped_bcast(pkt[ARP].psrc, pkt[ARP].pdst, m)

    q.time = pkt.time
    return q


def dst_mac(pkt, gw_mac):
    # Select Ethernet destination MAC after rewriting.
    if IP not in pkt:
        return gw_mac
    dst = pkt[IP].dst
    if is_bcast(dst):
        return BCAST
    if UDP in pkt and int(pkt[UDP].dport) in PROTO_MAC:
        return PROTO_MAC[int(pkt[UDP].dport)]
    return mcast_mac(dst) if is_mcast(dst) else gw_mac


def gw_egress_iface(pkt, row):
    # Find which gateway interface should observe this packet leaving.
    fallback = row.get("simulated_ip")
    if IP in pkt:
        dst = pkt[IP].dst
        return safe_route_iface(GW, dst, fallback) if is_bcast(dst) or is_mcast(dst) else safe_route_iface(GW, dst, fallback)
    if ARP in pkt:
        pdst = pkt[ARP].pdst
        return safe_route_iface(GW, pdst, fallback) if pdst and pdst != "0.0.0.0" and not is_bcast(pdst) else safe_route_iface(GW, fallback)
    return safe_route_iface(GW, fallback)


def keep_expected_if_missing(pkt):
    # Some discovery/broadcast packets may not appear in gateway capture but should be kept if missing.
    if ARP in pkt:
        addrs = {pkt[ARP].psrc, pkt[ARP].pdst}
        return any(a.startswith("172.") or a == "0.0.0.0" for a in addrs)
    if IP in pkt and (is_bcast(pkt[IP].dst) or is_mcast(pkt[IP].dst)):
        return True
    return Ether in pkt and pkt[Ether].dst.lower() == BCAST


@dataclass(frozen=True)
class SenderMeta:
    row: dict
    original_ip: str
    container: str
    iface: str
    src_mac: str
    gw_mac: str


def tcp_payload_len(pkt):
    if IP not in pkt or TCP not in pkt:
        return 0
    ip = IP(bytes(pkt.copy()[IP]))
    return max(0, int(ip.len) - int(ip.ihl) * 4 - int(ip[TCP].dataofs) * 4)


def normalize_tcp_seq_ack(packets):
    # Rebuild TCP sequence/ACK values consistently after packet rewriting.
    next_seq = {}

    def key(pkt):
        return pkt[IP].src, pkt[IP].dst, int(pkt[TCP].sport), int(pkt[TCP].dport)

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue

        k = key(pkt)
        rk = k[1], k[0], k[3], k[2]
        next_seq.setdefault(k, int(pkt[TCP].seq))
        pkt[TCP].seq = next_seq[k]

        if int(pkt[TCP].flags) & 0x10 and rk in next_seq:
            pkt[TCP].ack = next_seq[rk]

        advance = tcp_payload_len(pkt)
        flags = int(pkt[TCP].flags)
        next_seq[k] += advance + bool(flags & 0x02) + bool(flags & 0x01)
        fix(pkt)

    return packets


def build_rewritten(original_pcap, topo, workdir, keep_unmapped=False):
    # Convert the original PCAP into packets valid for the simulated topology.
    rows, m = by_key(topo, "original_ip"), ipmap(topo)
    sim_to_orig = {r["simulated_ip"]: r["original_ip"] for r in active_rows(topo)}
    meta_cache, egress_cache, packets, meta = {}, {}, [], []
    skipped = 0

    def get_meta(orig_ip):
        # Cache sender container/interface/MAC information.
        if orig_ip not in meta_cache:
            row = rows[orig_ip]
            container = PREFIX + row["service_name"]
            iface = container_iface(container, row["gateway_ip"])
            gw_iface = route_iface(GW, row["simulated_ip"])
            meta_cache[orig_ip] = SenderMeta(row, orig_ip, container, iface, iface_mac(container, iface), iface_mac(GW, gw_iface))
        return meta_cache[orig_ip]

    def mac_for_sim_ip(sim_ip, fallback_mac):
        # Resolve simulated IP to the corresponding container MAC.
        orig = sim_to_orig.get(sim_ip)
        if not orig:
            return fallback_mac
        try:
            return get_meta(orig).src_mac
        except Exception:
            return fallback_mac

    def cached_gw_egress_iface(pkt, row):
        # Cache gateway egress interface lookups.
        fallback = row.get("simulated_ip", "")
        key = ("IP", pkt[IP].dst, fallback) if IP in pkt else ("ARP", pkt[ARP].pdst, fallback) if ARP in pkt else ("OTHER", fallback)
        if key not in egress_cache:
            egress_cache[key] = gw_egress_iface(pkt, row)
        return egress_cache[key]

    all_packets = rdpcap(str(original_pcap))
    total = len(all_packets)
    last_progress = -1

    print("[*] Rewriting progress   :   0%", end="", flush=True)

    for idx, pkt in enumerate(all_packets, 1):
        progress = int((idx / total) * 100)
        if progress != last_progress:
            print(f"\r[*] Rewriting progress   : {progress:3d}%", end="", flush=True)
            last_progress = progress

        orig_ip = sender_ip(pkt, topo)
        if not orig_ip or orig_ip not in rows:
            skipped += 1
            continue

        sm = get_meta(orig_ip)
        q = rewrite_arp(pkt, m) if ARP in pkt else rewrite_ip(pkt, m, keep_unmapped)
        if q is None:
            skipped += 1
            continue

        # Rewrite Ethernet source/destination addresses.
        q[Ether].src = sm.src_mac
        if ARP in q:
            q[ARP].hwsrc = sm.src_mac
            if int(q[ARP].op) == 1:
                q[Ether].dst, q[ARP].hwdst = BCAST, ZERO
            else:
                target_mac = mac_for_sim_ip(q[ARP].pdst, sm.gw_mac)
                q[Ether].dst = q[ARP].hwdst = target_mac
        else:
            q[Ether].dst = dst_mac(q, sm.gw_mac)
            q = fix(q)

        egress_iface = cached_gw_egress_iface(q, sm.row)
        if not egress_iface:
            skipped += 1
            continue

        packets.append(pad_eth_min(q))
        meta.append({
            "container": sm.container,
            "iface": sm.iface,
            "gw_iface": egress_iface,
            "original_ip": orig_ip,
            "replay": replayable(q),
            "tcp": tcp(q),
            "udp": udp(q),
            "keep_if_missing": keep_expected_if_missing(q),
        })

    print()
    if not packets:
        raise RuntimeError("No replayable packets produced.")

    packets = normalize_tcp_seq_ack(packets)
    pcap = workdir / "rewritten_all_packets.pcap"
    wrpcap(str(pcap), packets, linktype=1)

    print(f"[*] Rewrite completed    : {len(packets)} replayable packets", flush=True)
    print(f"[*] Skipped packets      : {skipped}", flush=True)
    return pcap, packets, meta


def write_sender(workdir):
    # Small helper script that sends packets by index inside a container network namespace.
    (workdir / "sender.py").write_text(r'''
import argparse, json, sys
from scapy.all import rdpcap, sendp

ap = argparse.ArgumentParser()
ap.add_argument("--pcap", required=True)
args = ap.parse_args()
pkts = rdpcap(args.pcap)

for line in sys.stdin:
    try:
        msg = json.loads(line)
        sendp(pkts[int(msg["i"])], iface=msg["iface"], verbose=False)
        print('{"ok":true}', flush=True)
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}), flush=True)
'''.lstrip(), encoding="utf-8")


def start_sender(container, workdir, pcap_name):
    # Start a sender process attached to the target container network namespace.
    return subprocess.Popen(
        [
            "docker", "run", "--rm", "-i",
            "--network", f"container:{container}",
            "--privileged",
            "-v", f"{workdir.resolve()}:/work",
            SCAPY_IMAGE,
            "/work/sender.py",
            "--pcap", f"/work/{pcap_name}",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


def send_pkt(proc, i, iface):
    # Ask sender.py to transmit one packet.
    proc.stdin.write(json.dumps({"i": i, "iface": iface}) + "\n")
    proc.stdin.flush()

    line = proc.stdout.readline().strip()
    if not line:
        raise RuntimeError(proc.stderr.read())

    res = json.loads(line)
    if not res.get("ok"):
        raise RuntimeError(res.get("error", "send failed"))


def stop_all(procs):
    # Stop all sender containers.
    for p in procs.values():
        try:
            p.stdin.close()
            p.wait(timeout=3)
        except Exception:
            p.kill()


def suppress_noise(containers):
    # Suppress local TCP RST and ICMP errors that could pollute replay traffic.
    rule = (
        "iptables -I OUTPUT 1 -p icmp --icmp-type destination-unreachable -j DROP 2>/dev/null || true; "
        "iptables -I OUTPUT 1 -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true; "
        "ip6tables -I OUTPUT 1 -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true"
    )
    targets = {c2 for c in containers for c2 in (c, f"{c}-route") if c.startswith(PREFIX) or c2 == c}
    for c in sorted(targets):
        try:
            sh(c, rule)
        except Exception:
            pass


def packet_direction(pkt):
    # Direction is used to decide when configured delay should affect the replay.
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if ARP in pkt:
        return pkt[ARP].psrc, pkt[ARP].pdst
    return None


def gateway_delay_seconds(src, dst, cache):
    # Read directional delay rule from the gateway container.
    key = (src, dst)
    if key not in cache:
        try:
            out = sh(GW, f"cat /tmp/replay_delay_rules/{src}__{dst}.ms 2>/dev/null || true").strip()
            cache[key] = float(out) / 1000.0 if out else 0.0
        except Exception:
            cache[key] = 0.0
    return cache[key]


def replay(pcap, packets, meta, multiplier, workdir):
    # Replay packets globally in original order.
    write_sender(workdir)

    containers = sorted({m["container"] for m in meta if m["replay"]})
    suppress_noise(containers)
    senders = {c: start_sender(c, workdir, pcap.name) for c in containers}

    mult = multiplier if multiplier and multiplier > 0 else 1.0
    sent = skipped = 0
    t0 = time.monotonic()
    total = len(packets)
    last_progress = -1
    last_ts = last_dir = None
    delay_cache = {}

    try:
        print("[*] Starting live replay : ARP/IP all protocols")

        for i, pkt in enumerate(packets):
            progress = int(((i + 1) / total) * 100)
            if progress != last_progress:
                print(f"\r[*] Replay progress      : {progress:3d}%", end="", flush=True)
                last_progress = progress

            curr_ts = float(pkt.time)
            curr_dir = packet_direction(pkt)

            if last_ts is not None:
                # Preserve original gap, scaled by multiplier.
                original_gap = max(0.0, (curr_ts - last_ts) / mult)

                # If direction changes, apply delay from the previous direction.
                extra_delay = gateway_delay_seconds(*last_dir, delay_cache) if curr_dir and last_dir and curr_dir != last_dir else 0.0

                time.sleep(original_gap + extra_delay)

            if meta[i]["replay"]:
                send_pkt(senders[meta[i]["container"]], i, meta[i]["iface"])
                sent += 1
            else:
                skipped += 1

            last_ts, last_dir = curr_ts, curr_dir

        print()

    finally:
        stop_all(senders)

    print(f"[*] Live sent packets    : {sent}")
    print(f"[*] Replay skipped       : {skipped}")
    print(f"[*] Replay elapsed       : {time.monotonic() - t0:.6f}s")


def gw_cleanup():
    # Remove temporary capture files from the gateway.
    try:
        sh(GW, f"rm -f {ANY_TMP} {ANY_LOG} {IFACE_TMP}*.pcap {IFACE_LOG}*.log")
    except Exception:
        pass


def start_capture(iface, tmp, log):
    # Start tcpdump on gateway; interface captures use outbound direction only.
    direction = "" if iface == "any" else "-Q out "
    pid = sh(
        GW,
        f"rm -f {tmp} {log}; "
        f"nohup tcpdump -U {direction}-i {iface} -nn -e -s 0 "
        f"-w {tmp} >{log} 2>&1 & echo $!",
    )
    if not pid:
        raise RuntimeError(f"Could not start tcpdump on gw:{iface}")
    return pid


def stop_capture(pid):
    # Stop tcpdump process.
    if pid:
        try:
            sh(GW, f"kill {pid} 2>/dev/null || true")
        except Exception:
            pass


def copy_from_gw(tmp, out):
    # Copy capture file from gateway container to host.
    out = Path(out).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["docker", "cp", f"{GW}:{tmp}", str(out)], check=True)
    return out


def sig(pkt):
    # Packet signature for matching observed packets with expected rewritten packets.
    if IP in pkt:
        proto = int(pkt[IP].proto)
        sport = dport = flags = seq = ack = plen = ""
        dns_id = dns_name = dns_type = ""

        if TCP in pkt:
            sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
            flags, seq, ack = int(pkt[TCP].flags), int(pkt[TCP].seq), int(pkt[TCP].ack)
            plen = len(bytes(pkt[TCP].payload))
        elif UDP in pkt:
            sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            plen = len(bytes(pkt[UDP].payload))
            if DNS in pkt:
                dns_id = int(pkt[DNS].id)
                if pkt[DNS].qd:
                    dns_name = bytes(pkt[DNS].qd.qname).decode(errors="ignore").lower().rstrip(".")
                    dns_type = int(pkt[DNS].qd.qtype)
        elif ICMP in pkt:
            sport, dport = int(pkt[ICMP].type), int(pkt[ICMP].code)
            plen = len(bytes(pkt[ICMP].payload))

        return ("IP", pkt[IP].src, pkt[IP].dst, proto, sport, dport, flags, seq, ack, plen, dns_id, dns_name, dns_type, payload_hash(pkt))

    if ARP in pkt:
        return "ARP", int(pkt[ARP].op), pkt[ARP].psrc, pkt[ARP].pdst, payload_hash(pkt)

    return None


def clean_capture(captures, expected, meta, out_pcap, allow_missing=False):
    # Filter gateway captures to keep only expected replay packets.
    captures = [Path(c) for c in captures if c]
    observed, skipped_other = [], 0

    for cap in captures:
        if not cap.exists():
            continue
        for p in rdpcap(str(cap)):
            if IP not in p and ARP not in p:
                skipped_other += 1
                continue
            q = pad_eth_min(p.copy())
            q.time = p.time
            observed.append(q)

    first_expected_time = min((float(p.time) for p in expected if replayable(p)), default=0.0)
    first_observed_time = min((float(p.time) for p in observed), default=time.time())

    # Build lookup from expected packet signatures to their original indexes.
    expected_by_sig = defaultdict(list)
    for i, exp in enumerate(expected):
        if replayable(exp) and (s := sig(exp)):
            expected_by_sig[s].append(i)

    final_by_index = {}
    observed_kept = 0

    # Keep only captured packets that match expected replay signatures.
    for obs in observed:
        queue = expected_by_sig.get(sig(obs))
        if not queue:
            continue
        while queue and queue[0] in final_by_index:
            queue.pop(0)
        if queue:
            idx = queue.pop(0)
            final_by_index[idx] = obs
            observed_kept += 1

    observed_indexes = lambda: sorted(final_by_index)

    def fallback_time_for_index(i):
        # Estimate timestamp for expected packets missing from capture.
        indexes = observed_indexes()
        if prev := [j for j in indexes if j < i]:
            j = max(prev)
            return float(final_by_index[j].time) + max(0.000001, float(expected[i].time) - float(expected[j].time))
        if nxt := [j for j in indexes if j > i]:
            j = min(nxt)
            return float(final_by_index[j].time) - max(0.000001, float(expected[j].time) - float(expected[i].time))
        return first_observed_time + max(0.0, float(expected[i].time) - first_expected_time)

    fallback_added = 0
    for i, exp in enumerate(expected):
        if not replayable(exp) or i in final_by_index:
            continue
        keep_missing = meta[i].get("keep_if_missing", False) if i < len(meta) else keep_expected_if_missing(exp)
        if not keep_missing and not allow_missing:
            continue
        q = pad_eth_min(exp.copy())
        q.time = fallback_time_for_index(i)
        final_by_index[i] = q
        fallback_added += 1

    def keep_clean_arp(pkt):
        # Remove gateway/container management ARP noise.
        if ARP not in pkt:
            return True
        psrc, pdst = pkt[ARP].psrc, pkt[ARP].pdst
        if psrc.endswith(".254") or pdst.endswith(".254") or psrc.startswith("10.") or pdst.startswith("10."):
            return False
        return any(x.startswith(("172.", "169.254.")) or x == "0.0.0.0" for x in (psrc, pdst))

    final = [p for i, p in sorted(final_by_index.items()) if keep_clean_arp(p)]

    # Ensure timestamps are strictly increasing in the output PCAP.
    last = None
    for pkt in final:
        if last is not None and float(pkt.time) <= last:
            pkt.time = last + 0.000001
        last = float(pkt.time)

    out = Path(out_pcap).resolve()
    wrpcap(str(out), final, linktype=1)

    print(f"[*] Clean gateway egress :    {out}")
    print(f"[*] Observed kept        : {observed_kept}")
    print(f"[*] Fallback added       : {fallback_added}")
    print(f"[*] Final packets        : {len(final)}")
    print(f"[*] Expected packets     : {sum(map(replayable, expected))}")
    print(f"[*] Skipped other        : {skipped_other}")
    return out


def append_gt(path, row):
    # Append one replay execution to ground-truth CSV.
    path = Path(path)
    rows = []

    if path.exists():
        with path.open(newline="", encoding="utf-8") as f:
            rows = [{k: old.get(k, "") for k in GT_FIELDS} for old in csv.DictReader(f)]

    row = {k: row.get(k, "") for k in GT_FIELDS}
    base_sample = row["sample_id"]
    versions = []

    for r in rows:
        sid = r.get("sample_id", "")
        if sid == base_sample:
            versions.append(1)
        elif sid.startswith(base_sample + "_"):
            try:
                versions.append(int(sid.rsplit("_", 1)[1]))
            except Exception:
                pass

    row["sample_id"] = f"{base_sample}_{max(versions, default=0) + 1}"
    rows.append(row)

    for i, r in enumerate(rows, 1):
        r["execution_id"] = str(i)

    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=GT_FIELDS)
        w.writeheader()
        w.writerows(rows)


def gt_row(pcap, multiplier, label, start, end, status, notes):
    # Create one ground-truth row for this replay run.
    return {
        "sample_id": Path(pcap).stem,
        "traffic_label": label,
        "replay_start_time_utc": utc(start),
        "replay_end_time_utc": utc(end),
        "replay_multiplier": str(multiplier),
        "status": status,
        "notes": notes,
    }


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default="")
    ap.add_argument("--topology", default="simulated_topology.json")
    ap.add_argument("--label", required=True, choices=["benign", "malicious"])
    ap.add_argument("--multiplier", type=float, default=1.0)
    ap.add_argument("--ground-truth", default="ground_truth.csv")
    ap.add_argument("--notes", default="")
    ap.add_argument("--capture-out", default="gateway_capture_any.pcap")
    ap.add_argument("--clean-out", default="gateway_egress.pcap")
    ap.add_argument("--keep-unmapped", action="store_true")
    ap.add_argument("--allow-missing-fallback", action="store_true")
    ap.add_argument("--no-filter", action="store_true")
    ap.add_argument("--post-capture-wait", type=float, default=2.0)
    return ap.parse_args()


def main():
    args = parse_args()
    topo = load_json(args.topology)
    original = Path(args.pcap or topo.get("pcap_file", "")).expanduser().resolve()
    if not original.exists():
        raise FileNotFoundError(original)

    print(f"[*] Sample ID            : {original.stem}")
    print(f"[*] Multiplier           : {args.multiplier}")
    print("[*] Capture point        : GW outbound interfaces, tcpdump -Q out")

    start = end = now()
    status = "failed"
    notes = args.notes.strip()
    any_pid = ""
    iface_pids = []
    iface_captures = []
    meta = []
    expected = []

    try:
        ensure_image()
        with tempfile.TemporaryDirectory(prefix="gateway_replay_", dir=".") as d:
            workdir = Path(d).resolve()
            gw_cleanup()

            # Rewrite original PCAP into simulated topology.
            replay_pcap, expected, meta = build_rewritten(original, topo, workdir, args.keep_unmapped)

            iface_nums = sorted(
                int(iface.replace("eth", ""))
                for iface in {m["gw_iface"] for m in meta}
            )

            if iface_nums:
                first_iface = iface_nums[0]
                last_iface = iface_nums[-1]

                if first_iface == last_iface:
                    iface_text = f"eth{first_iface}"
                else:
                    iface_text = f"eth{first_iface}-eth{last_iface}"

                print(
                    f"[*] GW egress capture    : "
                    f"{GW}:{iface_text} (-Q out)"
                )

            # Start gateway captures before replay.
            any_pid = start_capture("any", ANY_TMP, ANY_LOG)

            for i, iface in enumerate(sorted({m["gw_iface"] for m in meta})):
                tmp = f"{IFACE_TMP}{i}.pcap"
                log = f"{IFACE_LOG}{i}.log"
                iface_pids.append((start_capture(iface, tmp, log), tmp, iface))

            time.sleep(1)
            start = now()

            # Replay rewritten packets with timing and delay rules.
            replay(replay_pcap, expected, meta, args.multiplier, workdir)
            status = "completed"

    except Exception as e:
        notes = f"{notes}; replay_error={e}" if notes else f"replay_error={e}"
        raise

    finally:
        end = now()
        try:
            # Stop captures and copy outputs back to host.
            time.sleep(args.post_capture_wait)
            stop_capture(any_pid)
            for pid, _, _ in iface_pids:
                stop_capture(pid)

            if any_pid:
                copy_from_gw(ANY_TMP, args.capture_out)

            for _, tmp, iface in iface_pids:
                cap = copy_from_gw(tmp, Path(f"gateway_iface_{iface}.pcap").resolve())
                iface_captures.append(cap)

            # Clean gateway egress capture to expected replay traffic only.
            if iface_captures and not args.no_filter:
                clean_capture(iface_captures, expected, meta, args.clean_out, args.allow_missing_fallback)

        except Exception as e:
            notes = f"{notes}; capture_or_filter_error={e}" if notes else f"capture_or_filter_error={e}"
            print(f"[!] Warning: {e}")

        # Always update ground-truth metadata.
        append_gt(args.ground_truth, gt_row(str(original), args.multiplier, args.label, start, end, status, notes))
        print(f"[*] Ground truth updated : {args.ground_truth}")
        gw_cleanup()

    print("[+] Gateway replay finished.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)