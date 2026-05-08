#!/usr/bin/env python3

from __future__ import annotations

import argparse, csv, hashlib, json, subprocess, sys, tempfile, time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from scapy.all import ARP, BOOTP, DNS, Ether, ICMP, IP, TCP, UDP, rdpcap, wrpcap
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

# Well-known IPv4 multicast/broadcast MAC addresses for common discovery
# protocols. Without these, multicast replay would be routed to the gateway MAC
# instead of the correct Ethernet destination.
PROTO_MAC = {
    137: BCAST,
    5353: "01:00:5e:00:00:fb",
    5355: "01:00:5e:00:00:fc",
    1900: "01:00:5e:7f:ff:fa",
}

# Stable ground-truth schema consumed later by the Zeek labeling step.
GT_FIELDS = [
    "execution_id", "sample_id", "attack_class", "traffic_label",
    "sender_count", "sender_containers", "sender_interfaces",
    "replay_start_time_utc", "replay_end_time_utc", "replay_multiplier",
    "status", "notes",
]


def run(cmd, **kw):
    """Run a host command and fail fast if the command exits non-zero."""
    return subprocess.run([str(x) for x in cmd], text=True, capture_output=True, check=True, **kw)


def sh(container: str, cmd: str) -> str:
    """Run a shell command inside a Docker container and return stdout."""
    return run(["docker", "exec", container, "sh", "-lc", cmd]).stdout.strip()


def now() -> datetime:
    """Return the current UTC timestamp for replay metadata."""
    return datetime.now(timezone.utc)


def utc(dt: datetime) -> str:
    """Serialize a datetime in the compact UTC format used by ground_truth.csv."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: str | Path):
    """Load a JSON file such as simulated_topology.json."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def ensure_image() -> None:
    """Build the small Scapy replay image if it is not already available locally."""
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
    """Return topology rows that represent real simulated hosts."""
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
    """Index active topology rows by a selected field."""
    return {r[key]: r for r in active_rows(topo)}


def dhcp_owner(topo):
    """Find which simulated host should send DHCP packets with source 0.0.0.0."""
    services = by_key(topo, "service_name")

    for r in topo.get("mapping", []):
        if r.get("sim_type") == "dhcp_zero" or r.get("original_ip") == "0.0.0.0":
            if r.get("service_name") in services:
                return services[r["service_name"]]

    internals = [r for r in active_rows(topo) if r.get("sim_type") == "internal"]
    return min(internals, key=lambda r: r["service_name"], default=None)


def ipmap(topo):
    """Build the original-IP to simulated-IP mapping used during packet rewriting."""
    return {
        **{r["original_ip"]: r["simulated_ip"] for r in active_rows(topo)},
        "0.0.0.0": "0.0.0.0",
    }


def route_iface(container, ip):
    """Ask Linux which interface would be used to route traffic to an IP."""
    return sh(
        container,
        f"ip route get {ip} | awk '{{for(i=1;i<=NF;i++) if($i==\"dev\"){{print $(i+1); exit}}}}'",
    )


def safe_route_iface(container, ip, fallback_ip=None):
    """Try one or more candidate IPs and return the first routable interface."""
    for candidate in (ip, fallback_ip):
        if not candidate:
            continue
        try:
            iface = route_iface(container, candidate)
            if iface:
                return iface
        except Exception:
            pass
    return ""


def container_iface(container, gateway_ip):
    """Find the interface inside a sender container that points toward its gateway."""
    for c in (f"{container}-route", container):
        try:
            if iface := route_iface(c, gateway_ip):
                return iface
        except Exception:
            pass
    raise RuntimeError(f"Could not discover interface for {container} towards {gateway_ip}")


def iface_mac(container, iface):
    """Read the MAC address assigned to a container interface."""
    if not (mac := sh(container, f"cat /sys/class/net/{iface}/address")):
        raise RuntimeError(f"Could not read MAC for {container}:{iface}")
    return mac.lower()


def is_bcast(ip):
    """Detect IPv4 limited or subnet broadcast addresses."""
    return ip == "255.255.255.255" or ip.endswith(".255")


def is_mcast(ip):
    """Detect IPv4 multicast addresses safely."""
    try:
        return ip_address(ip).is_multicast
    except Exception:
        return False


def mcast_mac(ip):
    """Convert an IPv4 multicast address to the corresponding Ethernet multicast MAC."""
    low23 = int(ip_address(ip)) & 0x7FFFFF
    return f"01:00:5e:{(low23 >> 16) & 0x7F:02x}:{(low23 >> 8) & 0xFF:02x}:{low23 & 0xFF:02x}"


def mapped_bcast(old_src, old_dst, m):
    """Rewrite a broadcast address into the simulated subnet when possible."""
    if old_dst == "255.255.255.255" or not old_dst.endswith(".255"):
        return old_dst
    src = m.get(old_src)
    return old_dst if not src or src == "0.0.0.0" else ".".join(src.split(".")[:3] + ["255"])


def has(pkt, *layers):
    """Small helper for checking that a packet contains all required Scapy layers."""
    return all(layer in pkt for layer in layers)


def is_dhcp(pkt):
    """Recognize DHCP client/server traffic based on UDP ports 67 and 68."""
    return has(pkt, IP, UDP) and {int(pkt[UDP].sport), int(pkt[UDP].dport)} == {67, 68}


def replayable(pkt):
    """Only ARP and IP packets are meaningful for this network replay."""
    return ARP in pkt or IP in pkt


def tcp(pkt):
    """Shortcut for IP/TCP packets."""
    return has(pkt, IP, TCP)


def udp(pkt):
    """Shortcut for IP/UDP packets."""
    return has(pkt, IP, UDP)


def eth(pkt):
    """Ensure a packet has an Ethernet header and correct EtherType."""
    q = pkt.copy()
    if Ether not in q:
        q = Ether(type=0x0806 if ARP in q else 0x0800) / q
    q[Ether].type = 0x0806 if ARP in q else 0x0800 if IP in q else q[Ether].type
    return q


def fix(pkt):
    """Delete checksums and lengths so Scapy recalculates them after rewriting."""
    if IP in pkt:
        for f in ("len", "chksum"):
            if hasattr(pkt[IP], f):
                delattr(pkt[IP], f)

    for layer in (TCP, UDP, ICMP):
        if layer in pkt and hasattr(pkt[layer], "chksum"):
            del pkt[layer].chksum

    return pkt

def pad_eth_min(pkt):
    """
    Preserve Ethernet minimum frame length in output PCAPs.

    tcpdump on Linux egress often captures short frames before NIC padding, so
    ACK/RST frames appear as 54 bytes instead of the original 60 bytes. Adding
    Ethernet padding makes the saved PCAP closer to the original capture length.
    """
    q = eth(pkt)
    missing = 60 - len(bytes(q))
    if missing > 0:
        q = q / Padding(b"\x00" * missing)
    return q


def payload_hash(pkt):
    """Hash the transport/application payload for capture matching."""
    for layer in (UDP, TCP, ICMP, ARP):
        if layer in pkt:
            data = pkt[layer] if layer == ARP else pkt[layer].payload
            return hashlib.sha1(bytes(data)).hexdigest()
    return hashlib.sha1(bytes(pkt)).hexdigest()


def sender_ip(pkt, topo):
    """Determine the original source host that should replay a packet."""
    rows = by_key(topo, "original_ip")

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
    """Rewrite IP packets from original addresses into simulated topology addresses."""
    if IP not in pkt:
        return None

    old_src, old_dst = pkt[IP].src, pkt[IP].dst
    special_dst = is_bcast(old_dst) or is_mcast(old_dst)

    if old_src not in m:
        return None
    if old_dst not in m and not special_dst and not keep_unmapped:
        return None

    q = eth(pkt)
    q[IP].src = m.get(old_src, old_src)

    if old_dst in m:
        q[IP].dst = m[old_dst]
    elif old_dst.endswith(".255"):
        q[IP].dst = mapped_bcast(old_src, old_dst, m)
    else:
        q[IP].dst = old_dst

    q.time = pkt.time
    return fix(q)


def rewrite_arp(pkt, m):
    """Rewrite ARP protocol addresses into the simulated topology."""
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
    """Choose the correct Ethernet destination MAC for the rewritten packet."""
    if IP not in pkt:
        return gw_mac

    dst = pkt[IP].dst
    if is_bcast(dst):
        return BCAST
    if UDP in pkt and int(pkt[UDP].dport) in PROTO_MAC:
        return PROTO_MAC[int(pkt[UDP].dport)]
    if is_mcast(dst):
        return mcast_mac(dst)
    return gw_mac


def gw_egress_iface(pkt, row):
    """
    Return the gateway interface where this rewritten packet should leave GW.

    For normal routed IP packets, this is route(GW, rewritten destination IP).
    For ARP/broadcast/multicast packets, Linux may not forward them as routed
    packets, so we use the sender-side gateway interface as the best capture
    interface and later keep missing expected broadcast/multicast/ARP packets.
    """
    fallback = row.get("simulated_ip")

    if IP in pkt:
        dst = pkt[IP].dst
        if is_bcast(dst) or is_mcast(dst):
            return safe_route_iface(GW, dst, fallback) or safe_route_iface(GW, fallback)
        return safe_route_iface(GW, dst, fallback)

    if ARP in pkt:
        pdst = pkt[ARP].pdst
        if pdst and pdst != "0.0.0.0" and not is_bcast(pdst):
            return safe_route_iface(GW, pdst, fallback)
        return safe_route_iface(GW, fallback)

    return safe_route_iface(GW, fallback)


def keep_expected_if_missing(pkt):
    """
    These packets may be generated by Scapy on a host-side interface but may not
    appear as Linux-routed outbound packets on GW with tcpdump -Q out.
    """
    if ARP in pkt:
        addrs = {pkt[ARP].psrc, pkt[ARP].pdst}
        return any(a.startswith("172.") or a == "0.0.0.0" for a in addrs)
    if IP in pkt and (is_bcast(pkt[IP].dst) or is_mcast(pkt[IP].dst)):
        return True
    if Ether in pkt and pkt[Ether].dst.lower() == BCAST:
        return True
    return False


@dataclass(frozen=True)
class SenderMeta:
    row: dict
    original_ip: str
    container: str
    iface: str
    src_mac: str
    gw_mac: str


def build_rewritten(original_pcap, topo, workdir, keep_unmapped=False):
    """Create one rewritten PCAP plus per-packet metadata for replay orchestration."""
    rows, m = by_key(topo, "original_ip"), ipmap(topo)
    sim_to_orig = {r["simulated_ip"]: r["original_ip"] for r in active_rows(topo)}

    cache = {}
    egress_cache = {}
    packets = []
    meta = []
    skipped = 0

    def get_meta(orig_ip):
        if orig_ip in cache:
            return cache[orig_ip]

        row = rows[orig_ip]
        container = PREFIX + row["service_name"]

        iface = container_iface(container, row["gateway_ip"])
        sender_gw_iface = route_iface(GW, row["simulated_ip"])

        cache[orig_ip] = SenderMeta(
            row=row,
            original_ip=orig_ip,
            container=container,
            iface=iface,
            src_mac=iface_mac(container, iface),
            gw_mac=iface_mac(GW, sender_gw_iface),
        )

        return cache[orig_ip]

    def mac_for_sim_ip(sim_ip, fallback_mac):
        orig = sim_to_orig.get(sim_ip)
        if not orig:
            return fallback_mac
        try:
            return get_meta(orig).src_mac
        except Exception:
            return fallback_mac

    def cached_gw_egress_iface(pkt, row):
        fallback = row.get("simulated_ip", "")

        if IP in pkt:
            key = ("IP", pkt[IP].dst, fallback)
        elif ARP in pkt:
            key = ("ARP", pkt[ARP].pdst, fallback)
        else:
            key = ("OTHER", fallback)

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

        q[Ether].src = sm.src_mac

        if ARP in q:
            q[ARP].hwsrc = sm.src_mac

            if int(q[ARP].op) == 1:
                q[Ether].dst = BCAST
                q[ARP].hwdst = ZERO
            else:
                target_mac = mac_for_sim_ip(q[ARP].pdst, sm.gw_mac)
                q[Ether].dst = target_mac
                q[ARP].hwdst = target_mac

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

    pcap = workdir / "rewritten_all_packets.pcap"
    wrpcap(str(pcap), packets, linktype=1)

    print(f"[*] Rewrite completed    : {len(packets)} replayable packets", flush=True)
    print(f"[*] Skipped packets      : {skipped}", flush=True)

    return pcap, packets, meta

def write_sender(workdir):
    """Write the tiny helper program that sends one selected packet per stdin command."""
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
    """Start a Scapy sender container sharing the network namespace of a simulated host."""
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
    """Tell a sender process to transmit packet index i on the given interface."""
    proc.stdin.write(json.dumps({"i": i, "iface": iface}) + "\n")
    proc.stdin.flush()

    line = proc.stdout.readline().strip()
    if not line:
        raise RuntimeError(proc.stderr.read())

    res = json.loads(line)
    if not res.get("ok"):
        raise RuntimeError(res.get("error", "send failed"))


def stop_all(procs):
    """Terminate all sender helper processes cleanly."""
    for p in procs.values():
        try:
            p.stdin.close()
            p.wait(timeout=3)
        except Exception:
            p.kill()


def suppress_noise(containers):
    """
    Suppress kernel-generated noise from simulated hosts.
    - Replayed UDP packets may arrive at containers with no real listening socket,
      so Linux generates ICMP port-unreachable packets.
    - Replayed TCP packets may hit closed ports or inconsistent TCP state, so Linux
      generates RST packets.
    - Those packets were not necessarily present in the original PCAP and make the
      replay less faithful.

    We try both <container> and <container>-route because the route sidecar usually
    has NET_ADMIN and shares the network namespace with the main service.
    """
    rule = (
        "iptables -I OUTPUT 1 -p icmp --icmp-type destination-unreachable -j DROP 2>/dev/null || true; "
        "iptables -I OUTPUT 1 -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true; "
        "ip6tables -I OUTPUT 1 -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true"
    )

    targets = set()
    for c in containers:
        targets.add(c)
        if c.startswith(PREFIX):
            targets.add(c + "-route")

    for c in sorted(targets):
        try:
            sh(c, rule)
        except Exception:
            pass

def load_gateway_delays():
    """Read configured one-way delay rules from the gateway container."""
    delays = {}

    try:
        out = sh(
            GW,
            "for f in /tmp/replay_delay_rules/*.ms; do "
            "[ -e \"$f\" ] || continue; "
            "name=$(basename \"$f\" .ms); "
            "delay=$(cat \"$f\"); "
            "echo \"$name $delay\"; "
            "done"
        )
    except Exception:
        return delays

    for line in out.splitlines():
        try:
            pair, delay_ms = line.strip().split()
            src, dst = pair.split("__", 1)
            delays[(src, dst)] = float(delay_ms) / 1000.0
        except Exception:
            continue

    return delays

def packet_direction(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if ARP in pkt:
        return pkt[ARP].psrc, pkt[ARP].pdst
    return None


def gateway_delay_seconds(src, dst, cache):
    key = (src, dst)
    if key in cache:
        return cache[key]

    path = f"/tmp/replay_delay_rules/{src}__{dst}.ms"

    try:
        out = sh(GW, f"cat {path} 2>/dev/null || true").strip()
        delay = float(out) / 1000.0 if out else 0.0
    except Exception:
        delay = 0.0

    cache[key] = delay
    return delay

def replay(pcap, packets, meta, multiplier, workdir):
    """Replay packets with original timing, plus configured one-way delay on direction changes."""
    write_sender(workdir)

    containers = sorted({m["container"] for m in meta if m["replay"]})
    suppress_noise(containers)
    senders = {c: start_sender(c, workdir, pcap.name) for c in containers}

    mult = multiplier if multiplier and multiplier > 0 else 1.0
    sent = skipped = 0
    t0 = time.monotonic()

    total = len(packets)
    last_progress = -1

    last_ts = None
    last_dir = None
    delay_cache = {}

    def packet_direction(pkt):
        if IP in pkt:
            return pkt[IP].src, pkt[IP].dst
        if ARP in pkt:
            return pkt[ARP].psrc, pkt[ARP].pdst
        return None

    def gateway_delay_seconds(src, dst):
        key = (src, dst)
        if key in delay_cache:
            return delay_cache[key]

        path = f"/tmp/replay_delay_rules/{src}__{dst}.ms"

        try:
            out = sh(GW, f"cat {path} 2>/dev/null || true").strip()
            delay_seconds = float(out) / 1000.0 if out else 0.0
        except Exception:
            delay_seconds = 0.0

        delay_cache[key] = delay_seconds
        return delay_seconds

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
                original_gap = max(0.0, (curr_ts - last_ts) / mult)
                extra_delay = 0.0

                if curr_dir and last_dir and curr_dir != last_dir:
                    extra_delay = gateway_delay_seconds(last_dir[0], last_dir[1])

                time.sleep(original_gap + extra_delay)

            if meta[i]["replay"]:
                send_pkt(senders[meta[i]["container"]], i, meta[i]["iface"])
                sent += 1
            else:
                skipped += 1

            last_ts = curr_ts
            last_dir = curr_dir

        print()

    finally:
        stop_all(senders)

    print(f"[*] Live sent packets    : {sent}")
    print(f"[*] Replay skipped       : {skipped}")
    print(f"[*] Replay elapsed       : {time.monotonic() - t0:.6f}s")

def gw_cleanup():
    """Remove temporary tcpdump files from the gateway container."""
    try:
        sh(GW, f"rm -f {ANY_TMP} {ANY_LOG} {IFACE_TMP}*.pcap {IFACE_LOG}*.log")
    except Exception:
        pass


def start_capture(iface, tmp, log):
    """Start tcpdump on the gateway for either debug any-capture or egress capture."""
    # Capture true GW egress for real interfaces. Keep 'any' only as debug.
    # -Q out means packets leaving this gateway interface after routing.
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
    """Stop a tcpdump process running inside the gateway."""
    if pid:
        try:
            sh(GW, f"kill {pid} 2>/dev/null || true")
        except Exception:
            pass


def copy_from_gw(tmp, out):
    """Copy a capture file from the gateway container to the host filesystem."""
    out = Path(out).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["docker", "cp", f"{GW}:{tmp}", str(out)], check=True)
    return out


def sig(pkt):
    """Build a packet signature used to match expected packets against observed captures."""
    if IP in pkt:
        proto = int(pkt[IP].proto)
        sport = dport = flags = seq = ack = plen = ""
        dns_id = dns_name = dns_type = ""

        if TCP in pkt:
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            flags = int(pkt[TCP].flags)
            seq = int(pkt[TCP].seq)
            ack = int(pkt[TCP].ack)
            plen = len(bytes(pkt[TCP].payload))
        elif UDP in pkt:
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
            plen = len(bytes(pkt[UDP].payload))
            if DNS in pkt:
                dns_id = int(pkt[DNS].id)
                if pkt[DNS].qd:
                    dns_name = bytes(pkt[DNS].qd.qname).decode(errors="ignore").lower().rstrip(".")
                    dns_type = int(pkt[DNS].qd.qtype)
        elif ICMP in pkt:
            sport = int(pkt[ICMP].type)
            dport = int(pkt[ICMP].code)
            plen = len(bytes(pkt[ICMP].payload))

        return (
            "IP", pkt[IP].src, pkt[IP].dst, proto,
            sport, dport, flags, seq, ack, plen,
            dns_id, dns_name, dns_type, payload_hash(pkt),
        )

    if ARP in pkt:
        return ("ARP", int(pkt[ARP].op), pkt[ARP].psrc, pkt[ARP].pdst, payload_hash(pkt))

    return None


def observed_as_eth(obs, fallback):
    """Normalize observed packets into Ethernet-framed packets when needed."""
    if Ether in obs:
        q = eth(obs.copy())
        q.time = obs.time
        return q

    fb = eth(fallback.copy())
    head = Ether(src=fb[Ether].src, dst=fb[Ether].dst, type=0x0806 if ARP in obs else 0x0800)

    if IP in obs:
        q = head / obs[IP].copy()
        q = fix(q)
    elif ARP in obs:
        q = head / obs[ARP].copy()
    else:
        q = fb

    q.time = obs.time
    return eth(q)


def normalize_expected_time(pkt, first_expected_time, first_observed_time):
    """Move fallback packets onto the observed replay time axis."""
    q = pad_eth_min(pkt.copy())
    q.time = first_observed_time + max(0.0, float(pkt.time) - first_expected_time)
    return q


def clean_capture(captures, expected, meta, out_pcap, allow_missing=False):
    """
    Build gateway_egress.pcap from GW outbound-interface captures.
    """
    captures = [Path(c) for c in captures if c]

    observed = []
    observed_counts = Counter()
    skipped_other = 0

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

            if s := sig(q):
                observed_counts[s] += 1

    first_expected_time = min((float(p.time) for p in expected if replayable(p)), default=0.0)
    first_observed_time = min((float(p.time) for p in observed), default=time.time())

    fallback = []
    fallback_added = 0

    for i, exp in enumerate(expected):
        if not replayable(exp):
            continue

        keep_missing = meta[i].get("keep_if_missing", False) if i < len(meta) else keep_expected_if_missing(exp)
        if not keep_missing and not allow_missing:
            continue

        s = sig(exp)
        if s and observed_counts.get(s, 0) > 0:
            observed_counts[s] -= 1
            continue

        q = normalize_expected_time(exp, first_expected_time, first_observed_time)
        fallback.append(q)
        fallback_added += 1

    def is_dhcp_pkt(pkt):
        return (
            IP in pkt
            and UDP in pkt
            and {int(pkt[UDP].sport), int(pkt[UDP].dport)} == {67, 68}
        )

    dhcp_times = [float(p.time) for p in fallback if is_dhcp_pkt(p)]
    bootstrap_end = max(dhcp_times) if dhcp_times else None

    if bootstrap_end is not None:
        first_arp_times = [
            float(p.time)
            for p in fallback
            if ARP in p and float(p.time) > bootstrap_end
        ][:2]

        if first_arp_times:
            bootstrap_end = max(first_arp_times)

        for p in observed:
            if not is_dhcp_pkt(p) and float(p.time) <= bootstrap_end:
                p.time = bootstrap_end + 0.000001

    tagged_final = []

    for p in observed:
        tagged_final.append((1, p))

    for p in fallback:
        tagged_final.append((0, p))

    tagged_final.sort(key=lambda item: (float(item[1].time), item[0]))

    final = [p for _, p in tagged_final]

    def keep_clean_arp(pkt):
        if ARP not in pkt:
            return True

        addrs = {pkt[ARP].psrc, pkt[ARP].pdst}

        # Drop leaked original-topology ARP, e.g.
        # Who has 10.6.13.1? Tell 172.30.11.11
        # 10.6.13.1 is at ...
        if any(a.startswith("10.") for a in addrs):
            return False

        # Keep simulated ARP and realistic probe/link-local ARP.
        return any(
            a.startswith("172.")
            or a == "0.0.0.0"
            or a.startswith("169.254.")
            for a in addrs
        )

    final = [p for p in final if keep_clean_arp(p)]

    last = None
    for pkt in final:
        if last is not None and float(pkt.time) <= last:
            pkt.time = last + 0.000001
        last = float(pkt.time)

    out = Path(out_pcap).resolve()
    wrpcap(str(out), final, linktype=1)

    print(f"[*] Clean gateway egress :    {out}")
    print(f"[*] Observed kept        : {len(observed)}")
    print(f"[*] Fallback added       : {fallback_added}")
    print(f"[*] Final packets        : {len(final)}")
    print(f"[*] Expected packets     : {sum(map(replayable, expected))}")
    print(f"[*] Skipped other        : {skipped_other}")
    return out

def append_gt(path, row):
    """Append a new replay execution to ground_truth.csv with auto-versioned sample IDs."""
    path = Path(path)
    rows = []

    if path.exists():
        with path.open(newline="", encoding="utf-8") as f:
            rows = [
                {k: old.get(k, "") for k in GT_FIELDS}
                for old in csv.DictReader(f)
            ]

    row = {k: row.get(k, "") for k in GT_FIELDS}

    base_sample = row["sample_id"]

    existing_versions = []

    for r in rows:
        sid = r.get("sample_id", "")

        if sid == base_sample:
            existing_versions.append(1)

        elif sid.startswith(base_sample + "_"):
            try:
                v = int(sid.rsplit("_", 1)[1])
                existing_versions.append(v)
            except Exception:
                pass

    next_version = max(existing_versions, default=0) + 1

    row["sample_id"] = f"{base_sample}_{next_version}"

    rows.append(row)

    for i, r in enumerate(rows, 1):
        r["execution_id"] = str(i)

    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=GT_FIELDS)
        w.writeheader()
        w.writerows(rows)


def gt_row(pcap, meta, multiplier, attack, start, end, status, notes):
    """Create the ground-truth row describing this replay execution."""
    containers = sorted({m["container"] for m in meta})
    interfaces = sorted({f'{m["container"]}:{m["iface"]}' for m in meta})
    attack = attack.strip()

    return {
        "sample_id": Path(pcap).stem,
        "attack_class": attack,
        "traffic_label": "benign" if not attack else "malicious",
        "sender_count": str(len(containers)),
        "sender_containers": json.dumps(containers),
        "sender_interfaces": json.dumps(interfaces),
        "replay_start_time_utc": utc(start),
        "replay_end_time_utc": utc(end),
        "replay_multiplier": str(multiplier),
        "status": status,
        "notes": notes,
    }


def parse_args():
    """Parse command-line arguments controlling replay, capture, and labeling metadata."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default="")
    ap.add_argument("--topology", default="simulated_topology.json")
    ap.add_argument("--multiplier", type=float, default=1.0)
    ap.add_argument("--ground-truth", default="ground_truth.csv")
    ap.add_argument("--attack-class", default="")
    ap.add_argument("--notes", default="")
    ap.add_argument("--capture-out", default="gateway_capture_any.pcap")
    ap.add_argument("--clean-out", default="gateway_egress.pcap")
    ap.add_argument("--keep-unmapped", action="store_true")
    ap.add_argument("--allow-missing-fallback", action="store_true")
    ap.add_argument("--no-filter", action="store_true")
    ap.add_argument("--post-capture-wait", type=float, default=2.0)
    
    return ap.parse_args()


def main():
    """Coordinate image setup, packet rewriting, replay, capture, cleaning, and ground truth."""
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

            replay_pcap, expected, meta = build_rewritten(
                original,
                topo,
                workdir,
                args.keep_unmapped,
            )


            for iface in sorted({m["gw_iface"] for m in meta}):
                print(f"[*] GW egress capture    : {GW}:{iface} (-Q out)")

            any_pid = start_capture("any", ANY_TMP, ANY_LOG)

            for i, iface in enumerate(sorted({m["gw_iface"] for m in meta})):
                tmp = f"{IFACE_TMP}{i}.pcap"
                log = f"{IFACE_LOG}{i}.log"
                iface_pids.append((start_capture(iface, tmp, log), tmp, iface))

            # Give tcpdump a moment to start writing before the first packet is sent.
            time.sleep(1)

            # Ground-truth timing starts immediately before replay and ends in finally.
            start = now()
            replay(replay_pcap, expected, meta, args.multiplier, workdir)
            status = "completed"

    except Exception as e:
        notes = f"{notes}; replay_error={e}" if notes else f"replay_error={e}"
        raise

    finally:
        end = now()
        try:
            time.sleep(args.post_capture_wait)

            stop_capture(any_pid)
            for pid, _, _ in iface_pids:
                stop_capture(pid)

            if any_pid:
                copy_from_gw(ANY_TMP, args.capture_out)  # debug only, not used for clean egress

            for _, tmp, iface in iface_pids:
                cap = copy_from_gw(tmp, Path(f"gateway_iface_{iface}.pcap").resolve())
                iface_captures.append(cap)

            if iface_captures and not args.no_filter:
                clean_capture(
                    iface_captures,
                    expected,
                    meta,
                    args.clean_out,
                    args.allow_missing_fallback,
                )

        except Exception as e:
            notes = f"{notes}; capture_or_filter_error={e}" if notes else f"capture_or_filter_error={e}"
            print(f"[!] Warning: {e}")

        append_gt(
            args.ground_truth,
            gt_row(str(original), meta, args.multiplier, args.attack_class, start, end, status, notes),
        )
        print(f"[*] Ground truth updated : {args.ground_truth}")
        gw_cleanup()

    print("[+] Gateway replay finished.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
