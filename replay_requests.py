#!/usr/bin/env python3
import argparse, json, shlex, subprocess, sys, time

PREFIX = "master-thesis-"
FALLBACK_HOST = "server.local"


def tshark(pcap, flt, fields):
    cmd = ["tshark", "-r", pcap, "-Y", flt, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=\t", "-E", "quote=n", "-E", "occurrence=f"]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def load_mapping(path):
    topo = json.load(open(path))
    return {r["original_ip"]: r for r in topo.get("mapping", []) if r.get("original_ip")}


def extract_events(pcap):
    events = []

    out = tshark(
        pcap,
        "dns.flags.response == 0 and ip.src and ip.dst and dns.qry.name",
        ["frame.time_epoch", "ip.src", "ip.dst", "dns.qry.name"],
    )
    for line in out.splitlines():
        parts = [x.strip() for x in line.split("\t")]
        if len(parts) < 4:
            continue
        ts, src, dst, name = parts[:4]
        name = name.lower().rstrip(".")
        if not ts or not src or not dst or not name:
            continue
        if dst.startswith("224.") or dst.startswith("239.") or dst.endswith(".255"):
            continue
        if name in {"wpad", "wpad.local"} or name.endswith(".local"):
            continue
        events.append(("dns", float(ts), src, name, None))

    out = tshark(
        pcap,
        "http.request and tcp and ip.src and ip.dst",
        ["frame.time_epoch", "ip.src", "ip.dst", "http.host", "http.request.method", "http.request.uri"],
    )
    for line in out.splitlines():
        parts = [x.strip() for x in line.split("\t")]
        if len(parts) < 5:
            continue
        ts, src, dst = parts[:3]
        host = parts[3].lower().rstrip(".") if len(parts) > 3 else ""
        method = parts[4].upper() if len(parts) > 4 else "GET"
        uri = parts[5] if len(parts) > 5 and parts[5] else "/"
        if not ts or not src or not dst:
            continue
        if dst.startswith("224.") or dst.startswith("239.") or dst.endswith(".255"):
            continue
        if method == "M-SEARCH":
            continue
        events.append(("http", float(ts), src, host, (method, uri)))

    events.sort(key=lambda x: (x[1], 0 if x[0] == "dns" else 1))
    return events


def replay(events, mapping, max_gap):
    events = [e for e in events if e[2] in mapping and mapping[e[2]].get("sim_type") == "internal"]

    if not events:
        print("No matching events found.")
        return

    prev_ts = None
    count = 0

    for kind, ts, src_ip, field1, field2 in events:
        if prev_ts is not None:
            gap = ts - prev_ts
            if gap > 0:
                time.sleep(min(gap, max_gap))
        prev_ts = ts

        row = mapping[src_ip]
        if not row.get("service_name"):
            print(f"WARNING: no service_name for {src_ip}", file=sys.stderr)
            continue

        container = PREFIX + row["service_name"]

        if kind == "dns":
            name = field1
            cmd = f"getent ahostsv4 {shlex.quote(name)} >/dev/null 2>&1 || nslookup {shlex.quote(name)} >/dev/null 2>&1 || true"
            print(f"[{ts:.3f}] {container} DNS -> {name}")
        else:
            method, uri = field2
            host = field1 or FALLBACK_HOST
            if not uri.startswith("/"):
                uri = "/" + uri
            cmd = (
                f"curl -sS -o /dev/null --max-time 10 "
                f"-X {shlex.quote(method)} "
                f"-H {shlex.quote('Host: ' + host)} "
                f"{shlex.quote('http://' + host + uri)} || true"
            )
            print(f"[{ts:.3f}] {container} HTTP -> {method} http://{host}{uri}")

        rc = subprocess.run(["docker", "exec", container, "sh", "-lc", cmd]).returncode
        if rc != 0:
            print(f"WARNING: failed in {container}", file=sys.stderr)
        count += 1

    print(f"\nDONE: Replayed {count} events.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--topology", required=True)
    ap.add_argument("--max-gap", type=float, default=2.0)
    args = ap.parse_args()

    replay(extract_events(args.pcap), load_mapping(args.topology), args.max_gap)


if __name__ == "__main__":
    main()