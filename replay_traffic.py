#!/usr/bin/env python3
from __future__ import annotations

import argparse, csv, hashlib, json, subprocess, sys, tempfile, time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from scapy.all import rdpcap, wrpcap, IP, TCP, UDP, DNS

DOCKER_PREFIX = "master-thesis-"
TCPREPLAY_IMAGE = "local/tcpreplay"
GW = f"{DOCKER_PREFIX}gw"

PRE_TMP, PRE_LOG = "/tmp/replay_pre.pcap", "/tmp/replay_pre.log"
MAIN_TMP, MAIN_LOG = "/tmp/replay_main.pcap", "/tmp/replay_main.log"

GT_FIELDS = [
    "execution_id", "sample_id", "attack_class", "traffic_label",
    "original_sender_ip", "mapped_sender_ip", "sender_container", "sender_interface",
    "replay_start_time_utc", "replay_end_time_utc", "replay_multiplier",
    "status", "notes",
]


def run(cmd, **kw):
    return subprocess.run(cmd, text=True, capture_output=True, check=True, **kw)


def sh(container, cmd):
    return run(["docker", "exec", container, "sh", "-lc", cmd]).stdout.strip()


def utc_now():
    return datetime.now(timezone.utc)


def utc_fmt(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def rows_by_ip(topology):
    return {r["original_ip"]: r for r in topology.get("mapping", []) if r.get("original_ip")}


def make_rewrite_map(topology):
    pairs = [
        f'{r["original_ip"]}:{r["simulated_ip"]}'
        for r in topology.get("mapping", [])
        if r.get("original_ip") and r.get("simulated_ip")
    ]
    if not pairs:
        raise ValueError("No usable IP mappings found in topology.")
    return ",".join(pairs)


def detect_sender(topology):
    by_ip, scores = rows_by_ip(topology), defaultdict(int)

    for e in topology.get("edges", []):
        row = by_ip.get(e.get("src_original_ip"))
        if not row or row.get("sim_type") != "internal":
            continue
        if row.get("service_name") in {"gw", "dns"}:
            continue

        scores[row["original_ip"]] += int(e.get("packet_count", 0)) * (
            10 if e.get("dst_service") is not None else 1
        )

    if not scores:
        raise ValueError("Could not auto-detect replay sender host.")

    return by_ip[max(scores, key=scores.get)]


def ensure_tcpreplay_image():
    if subprocess.run(["docker", "image", "inspect", TCPREPLAY_IMAGE], capture_output=True).returncode == 0:
        return

    with tempfile.TemporaryDirectory() as d:
        Path(d, "Dockerfile").write_text(
            "FROM alpine:3.20\n"
            "RUN apk add --no-cache tcpreplay\n"
            'ENTRYPOINT ["tcpreplay"]\n',
            encoding="utf-8",
        )
        print("[*] Building tcpreplay image")
        subprocess.run(["docker", "build", "-t", TCPREPLAY_IMAGE, d], check=True)


def route_iface(container, ip):
    return sh(
        container,
        f"ip route get {ip} | "
        "awk '{for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1); exit}}'",
    )


def sender_iface(container, gateway_ip):
    for c in (f"{container}-route", container):
        try:
            iface = route_iface(c, gateway_ip)
            if iface:
                return iface
        except Exception:
            pass
    raise RuntimeError(f"Could not discover sender interface for {container}")


def gw_iface(ip):
    iface = route_iface(GW, ip)
    if not iface:
        raise RuntimeError(f"Could not discover gateway interface towards {ip}")
    return iface


def iface_mac(container, iface):
    mac = sh(container, f"cat /sys/class/net/{iface}/address")
    if not mac:
        raise RuntimeError(f"Could not read MAC for {container}:{iface}")
    return mac.lower()


def cleanup():
    sh(GW, f"rm -f {PRE_TMP} {PRE_LOG} {MAIN_TMP} {MAIN_LOG}")


def start_capture(iface, tmp, log):
    pid = sh(
        GW,
        f"rm -f {tmp} {log}; nohup tcpdump -U -i {iface} -nn -s 0 "
        f"-w {tmp} >{log} 2>&1 & echo $!",
    )
    if not pid:
        raise RuntimeError(f"Could not start tcpdump on gw:{iface}")
    return pid


def stop_capture(pid):
    if pid:
        sh(GW, f"kill {pid} 2>/dev/null || true")


def copy_from_gw(tmp, out):
    out = Path(out).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["docker", "cp", f"{GW}:{tmp}", str(out)], check=True)
    return out


def rewrite_pcap(src, out, ipmap, gw_mac):
    src, out = Path(src).resolve(), Path(out).resolve()
    if not src.exists():
        raise FileNotFoundError(src)

    subprocess.run([
        "tcprewrite",
        f"--infile={src}",
        f"--outfile={out}",
        f"--srcipmap={ipmap}",
        f"--dstipmap={ipmap}",
        f"--enet-dmac={gw_mac}",
        "--fixcsum",
    ], check=True)
    return out


def pcap_count(pcap):
    return len(rdpcap(str(pcap)))


def replay(container, iface, pcap, multiplier):
    total = pcap_count(pcap)
    cmd = [
        "docker", "run", "--rm",
        "--network", f"container:{container}",
        "--cap-add", "NET_ADMIN",
        "--cap-add", "NET_RAW",
        "-v", f"{pcap.parent}:/work",
        TCPREPLAY_IMAGE,
        f"--intf1={iface}",
        f"--multiplier={multiplier}",
        "--stats=1",
        f"/work/{pcap.name}",
    ]

    print(f"[*] Replaying packets... 0/{total} 0.0%", end="", flush=True)

    proc = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
    last = 0

    for line in proc.stdout:
        if "Actual:" not in line or "packets" not in line:
            continue
        try:
            parts = line.replace(":", " ").split()
            last = max(last, int(parts[parts.index("Actual") + 1]))
            pct = min(100.0, last * 100 / total) if total else 0
            print(f"\r[*] Replaying packets... {last}/{total} {pct:.1f}%", end="", flush=True)
        except Exception:
            pass

    rc = proc.wait()
    print(f"\r[*] Replaying packets... {total}/{total} 100.0%")
    if rc:
        raise subprocess.CalledProcessError(rc, cmd)


def next_id(path):
    path = Path(path)
    if not path.exists():
        return "1"

    max_id = 0
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            x = str(row.get("execution_id", "")).strip()
            if x.isdigit():
                max_id = max(max_id, int(x))
    return str(max_id + 1)


def append_gt(path, row):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists()

    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=GT_FIELDS)
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def gt_row(path, pcap, sender, container, iface, multiplier, attack, start, end, status, notes):
    attack = attack.strip()
    return {
        "execution_id": next_id(path),
        "sample_id": Path(pcap).stem,
        "attack_class": attack,
        "traffic_label": "benign" if not attack else "malicious",
        "original_sender_ip": sender.get("original_ip", ""),
        "mapped_sender_ip": sender.get("simulated_ip", ""),
        "sender_container": container,
        "sender_interface": iface,
        "replay_start_time_utc": utc_fmt(start),
        "replay_end_time_utc": utc_fmt(end),
        "replay_multiplier": str(multiplier),
        "status": status,
        "notes": notes,
    }


# ---------- filter ----------

def digest(x):
    return hashlib.sha1(bytes(x)).hexdigest()


def noise(ip):
    return ip.startswith(("224.", "239.")) or ip.endswith(".255")


def first_src(pkts):
    return next((p[IP].src for p in pkts if IP in p), None)


def main_src(pkts):
    counts = Counter(p[IP].src for p in pkts if IP in p and not noise(p[IP].src))
    return counts.most_common(1)[0][0] if counts else None


def dsts_from_sender(pkts, sender):
    out = []
    for p in pkts:
        if IP in p and p[IP].src == sender and not noise(p[IP].dst) and p[IP].dst not in out:
            out.append(p[IP].dst)
    return out


def filter_ip_map(orig, replayed):
    o_sender, r_sender = first_src(orig), main_src(replayed)
    if not o_sender or not r_sender:
        raise RuntimeError("Could not detect sender IP for filtering.")

    ipmap = {r_sender: o_sender}
    for r_ip, o_ip in zip(dsts_from_sender(replayed, r_sender), dsts_from_sender(orig, o_sender)):
        ipmap[r_ip] = o_ip
    return o_sender, ipmap


def pkt_key(p, sender, ipmap):
    if IP not in p:
        return None

    src = ipmap.get(p[IP].src, p[IP].src)
    dst = ipmap.get(p[IP].dst, p[IP].dst)
    if src != sender:
        return None

    sport = dport = flags = seq = ack = dns_id = dns_name = dns_type = payload = ""

    if TCP in p:
        sport, dport = p[TCP].sport, p[TCP].dport
        flags, seq, ack = str(p[TCP].flags), int(p[TCP].seq), int(p[TCP].ack)

    if UDP in p:
        sport, dport = p[UDP].sport, p[UDP].dport

    if DNS in p:
        dns_id = int(p[DNS].id)
        if p[DNS].qd:
            dns_name = bytes(p[DNS].qd.qname).decode(errors="ignore").lower().rstrip(".")
            dns_type = int(p[DNS].qd.qtype)

    if UDP in p and dport in (137, 1900):
        payload = digest(p[UDP].payload)

    return (src, dst, p[IP].proto, sport, dport, flags, seq, ack, dns_id, dns_name, dns_type, payload)


def dup_window(k):
    proto, dport = k[2], k[4]
    if proto == 17 and dport == 137:
        return 0.0002
    if proto == 17 and dport in (5353, 5355, 1900):
        return 0.00001
    if proto == 17 and dport == 53:
        return 0.002
    if proto == 6:
        return 0.002
    return 0.00001


def grouped(pkts, sender, ipmap):
    raw = defaultdict(list)

    for p in pkts:
        k = pkt_key(p, sender, ipmap)
        if k:
            raw[k].append(p)

    clean = {}
    for k, ps in raw.items():
        ps.sort(key=lambda p: float(p.time))
        win = dup_window(k)
        clean[k], group = [], [ps[0]]

        for p in ps[1:]:
            if float(p.time) - float(group[-1].time) <= win:
                group.append(p)
            else:
                clean[k].append(group[-1])
                group = [p]

        clean[k].append(group[-1])

    return clean


def is_nbns(p):
    return UDP in p and p[UDP].dport == 137


def filter_pcap(original, replayed, out):
    orig, rep = rdpcap(str(original)), rdpcap(str(replayed))
    sender, ipmap = filter_ip_map(orig, rep)
    pool = grouped(rep, sender, ipmap)

    kept, missing = [], []

    for n, p in enumerate(orig, start=1):
        k = pkt_key(p, sender, ipmap)
        if not k:
            continue
        if k not in pool or not pool[k]:
            missing.append(n)
            continue
        kept.append(pool[k].pop(0) if is_nbns(p) else pool[k].pop())

    kept.sort(key=lambda p: float(p.time))
    wrpcap(str(out), kept)

    print(f"[*] Clean egress created : {Path(out).resolve()}")
    print(f"[*] Clean egress packets : {len(kept)}")
    print(f"[*] Missing packets      : {len(missing)}")


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--topology", default="simulated_topology.json")
    ap.add_argument("--rewritten", default="")
    ap.add_argument("--multiplier", type=float, default=1.0)
    ap.add_argument("--ground-truth", default="ground_truth.csv")
    ap.add_argument("--attack-class", default="")
    ap.add_argument("--notes", default="")
    ap.add_argument("--capture-pre-out", default="sender_capture.pcap")
    ap.add_argument("--capture-out", default="gateway_capture.pcap")
    ap.add_argument("--clean-out", default="gateway_egress.pcap")
    ap.add_argument("--no-filter", action="store_true")
    args = ap.parse_args()

    topology = load_json(args.topology)
    sender = detect_sender(topology)

    original_ip = sender.get("original_ip")
    simulated_ip = sender.get("simulated_ip")
    service = sender.get("service_name")
    gateway_ip = sender.get("gateway_ip")

    if not all([original_ip, simulated_ip, service, gateway_ip]):
        raise ValueError(f"Incomplete sender row: {sender}")

    attack = args.attack_class.strip()
    label = "benign" if not attack else "malicious"
    container = DOCKER_PREFIX + service
    rewritten = Path(args.rewritten or f"{Path(args.pcap).stem}_rewritten.pcap").resolve()

    print(f"[*] Replay label         : {label}")
    print(f"[*] Attack class         : {attack or '(none)'}")
    print(f"[*] Original sender      : {original_ip}")
    print(f"[*] Simulated sender     : {simulated_ip} ({container})")
    print(f"[*] Multiplier           : {args.multiplier}")

    iface = pre_pid = main_pid = ""
    start = None
    status = "failed"
    notes = args.notes.strip()

    try:
        iface = sender_iface(container, gateway_ip)
        gwi = gw_iface(simulated_ip)
        mac = iface_mac(GW, gwi)

        rewritten = rewrite_pcap(args.pcap, rewritten, make_rewrite_map(topology), mac)

        ensure_tcpreplay_image()
        cleanup()

        pre_pid = start_capture(gwi, PRE_TMP, PRE_LOG)
        main_pid = start_capture("any", MAIN_TMP, MAIN_LOG)

        time.sleep(1)
        start = utc_now()

        replay(container, iface, rewritten, args.multiplier)
        status = "completed"

    except Exception as e:
        notes = f"{notes}; replay_error={e}" if notes else f"replay_error={e}"
        raise

    finally:
        end = utc_now()
        start = start or end

        try:
            time.sleep(1)

            if pre_pid:
                stop_capture(pre_pid)
                copy_from_gw(PRE_TMP, args.capture_pre_out)

            if main_pid:
                stop_capture(main_pid)
                main_out = copy_from_gw(MAIN_TMP, args.capture_out)

                if not args.no_filter:
                    filter_pcap(args.pcap, main_out, Path(args.clean_out).resolve())

        except Exception as e:
            notes = f"{notes}; capture_or_filter_error={e}" if notes else f"capture_or_filter_error={e}"
            print(f"[!] Warning: {e}")

        append_gt(
            args.ground_truth,
            gt_row(
                args.ground_truth, args.pcap, sender, container, iface,
                args.multiplier, args.attack_class, start, end, status, notes
            ),
        )

        print(f"[*] Ground truth appended: {args.ground_truth}")

        try:
            cleanup()
        except Exception:
            pass

        try:
            if rewritten.exists():
                rewritten.unlink()
        except Exception:
            pass

    print("[+] Replay finished.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)