#!/usr/bin/env bash
set -euo pipefail

GW="${GW_CONTAINER:-master-thesis-gw}"
PREFIX="${CONTAINER_PREFIX:-master-thesis-}"

usage() {
  echo "Usage:"
  echo "  $0 set <SRC_IP> <DST_IP> <DELAY_MS>"
  echo "  $0 del <SRC_IP> <DST_IP>"
  echo "  $0 list"
  exit 1
}

die() { echo "ERROR: $*" >&2; exit 1; }
gw() { docker exec -u 0 "$GW" sh -lc "$1"; }

command -v docker >/dev/null 2>&1 || die "docker not found"
docker ps --format '{{.Names}}' | grep -qx "$GW" || die "Gateway '$GW' not running"

[ $# -ge 1 ] || usage
cmd="$1"; shift

case "$cmd" in
  set)  [ $# -eq 3 ] || usage; SRC="$1"; DST="$2"; DELAY="$3" ;;
  del)  [ $# -eq 2 ] || usage; SRC="$1"; DST="$2"; DELAY="" ;;
  list) [ $# -eq 0 ] || usage ;;
  *) usage ;;
esac

valid_ip() {
  python3 - "$1" <<'PY'
import ipaddress, sys
ipaddress.ip_address(sys.argv[1])
PY
}

ip_exists() {
  docker inspect $(docker ps --format '{{.Names}}' | grep -E "^${PREFIX}") \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
    | tr ' ' '\n' | grep -Fxq "$1"
}

validate_pair() {
  valid_ip "$SRC" || die "invalid source IP: $SRC"
  valid_ip "$DST" || die "invalid destination IP: $DST"
  [ "$SRC" != "$DST" ] || die "source and destination IP cannot be same"
  ip_exists "$SRC" || die "source IP does not exist: $SRC"
  ip_exists "$DST" || die "destination IP does not exist: $DST"

  if [ "$cmd" = "set" ]; then
    [[ "$DELAY" =~ ^[0-9]+$ ]] || die "delay must be integer ms"
  fi
}

list_rules() {
  echo "--- $GW"
  gw '
    for d in /sys/class/net/eth*; do
      [ -e "$d" ] || continue
      dev="${d##*/}"
      echo
      echo "dev=$dev"
      tc -s qdisc show dev "$dev" || true
      tc -s class show dev "$dev" 2>/dev/null || true
      tc -s filter show dev "$dev" parent 1: 2>/dev/null || true
    done
  '
}

[ "$cmd" = "list" ] && { list_rules; exit 0; }
validate_pair

gw "
set -euo pipefail

CMD='$cmd'
SRC='$SRC'
DST='$DST'
DELAY='$DELAY'

egress_dev() {
  ip route get \"\$1\" 2>/dev/null |
    awk '{for(i=1;i<=NF;i++) if(\$i==\"dev\"){print \$(i+1); exit}}'
}

mark_dir() {
  cksum_val=\$(printf '%s->%s' \"\$1\" \"\$2\" | cksum | awk '{print \$1}')
  echo \$(( (cksum_val % 4094) + 2 ))
}

dev=\$(egress_dev \"\$DST\")
[ -n \"\$dev\" ] || { echo \"ERROR: cannot find egress dev for \$DST\" >&2; exit 1; }

mark=\$(mark_dir \"\$SRC\" \"\$DST\")
classid=\"1:\$mark\"
handle=\"\$mark:\"

if [ \"\$CMD\" = set ]; then
  if ! tc qdisc show dev \"\$dev\" | grep -q 'htb 1:'; then
    tc qdisc del dev \"\$dev\" root 2>/dev/null || true
    tc qdisc add dev \"\$dev\" root handle 1: htb default 1
    tc class add dev \"\$dev\" parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit quantum 125000
  fi

  tc class show dev \"\$dev\" 2>/dev/null | grep -q \"class htb \$classid\" ||
    tc class add dev \"\$dev\" parent 1: classid \"\$classid\" htb rate 1000mbit ceil 1000mbit quantum 125000

  tc qdisc del dev \"\$dev\" parent \"\$classid\" handle \"\$handle\" 2>/dev/null || true
  tc qdisc add dev \"\$dev\" parent \"\$classid\" handle \"\$handle\" netem delay \"\${DELAY}ms\"

  tc filter del dev \"\$dev\" parent 1: protocol ip prio \"\$mark\" u32 2>/dev/null || true
  tc filter add dev \"\$dev\" parent 1: protocol ip prio \"\$mark\" u32 \
    match ip src \"\$SRC\"/32 \
    match ip dst \"\$DST\"/32 \
    flowid \"\$classid\"

  echo \"OK: gateway delay \$SRC -> \$DST = \${DELAY}ms on \$dev\"
  echo \"Check counters with: ./set_delay.sh list\"

else
  tc filter del dev \"\$dev\" parent 1: protocol ip prio \"\$mark\" u32 2>/dev/null || true
  tc qdisc del dev \"\$dev\" parent \"\$classid\" handle \"\$handle\" 2>/dev/null || true
  tc class del dev \"\$dev\" classid \"\$classid\" 2>/dev/null || true

  echo \"OK: removed gateway delay \$SRC -> \$DST on \$dev\"
fi
"