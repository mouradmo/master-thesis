#!/usr/bin/env bash
set -euo pipefail

GW="${GW_CONTAINER:-master-thesis-gw}"

usage() {
  echo "Usage:"
  echo "  $0 set <SRC_IP> <DST_IP> <DELAY_MS>   # apply delay only SRC -> DST"
  echo "  $0 del <SRC_IP> <DST_IP>              # remove delay only SRC -> DST"
  echo "  $0 list                               # show current rules"
  exit 1
}

gw() { docker exec -u 0 "$GW" sh -lc "$1"; }

need_docker() {
  command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 1; }
  docker ps --format '{{.Names}}' | grep -qx "$GW" || { echo "Gateway '$GW' not running"; exit 1; }
}
need_docker

[ $# -ge 1 ] || usage
cmd="$1"; shift

case "$cmd" in
  set) [ $# -eq 3 ] || usage; SRC="$1"; DST="$2"; DELAY="$3" ;;
  del) [ $# -eq 2 ] || usage; SRC="$1"; DST="$2" ;;
  list) [ $# -eq 0 ] || usage ;;
  *) usage ;;
esac

if [ "$cmd" = "list" ]; then
  gw '
    echo "=== iptables mangle/FORWARD ==="
    iptables -t mangle -S FORWARD || true
    echo
    echo "=== tc (eth*) ==="
    for d in $(ls /sys/class/net | grep -E "^eth"); do
      echo "--- $d ---"
      tc qdisc show dev "$d" || true
      tc class show dev "$d" 2>/dev/null || true
      tc filter show dev "$d" parent 1: 2>/dev/null || true
    done
  '
  exit 0
fi

gw_script='
set -euo pipefail
CMD="'"$cmd"'"
SRC="'"${SRC:-}"'"
DST="'"${DST:-}"'"
DELAY="'"${DELAY:-}"'"

egress_dev() {
  ip route get "$1" 2>/dev/null | awk "{for(i=1;i<=NF;i++) if(\$i==\"dev\"){print \$(i+1); exit}}"
}

# stable mark 1..4095
mark_dir() {
  local x
  x=$(printf "%s->%s" "$1" "$2" | cksum | awk "{print \$1}")
  echo $(( (x % 4095) + 1 ))
}

ensure_root_htb() {
  local dev="$1"
  # Create root HTB only if missing
  if ! tc qdisc show dev "$dev" | grep -q "htb 1:"; then
    # If something else is root, remove it (safe for this lab)
    tc qdisc del dev "$dev" root 2>/dev/null || true
    tc qdisc add dev "$dev" root handle 1: htb default 1
    tc class add dev "$dev" parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit quantum 125000
  fi
}

apply_delay() {
  local src="$1" dst="$2" delay="$3"
  local dev mark classid handle

  dev="$(egress_dev "$dst")"
  [ -n "$dev" ] || { echo "ERROR: cannot find egress interface for dst=$dst" >&2; exit 1; }

  mark="$(mark_dir "$src" "$dst")"
  classid="1:${mark}"
  handle="${mark}:"

  # 1) mark traffic
  iptables -t mangle -C FORWARD -s "$src" -d "$dst" -j MARK --set-mark "$mark" 2>/dev/null \
    || iptables -t mangle -A FORWARD -s "$src" -d "$dst" -j MARK --set-mark "$mark"

  # 2) ensure tc root exists on that egress interface
  ensure_root_htb "$dev"

  # 3) class per mark (idempotent)
  tc class show dev "$dev" 2>/dev/null | grep -q "class htb $classid" \
    || tc class add dev "$dev" parent 1: classid "$classid" htb rate 1000mbit ceil 1000mbit quantum 125000

  # 4) netem per mark (idempotent/update)
  tc qdisc del dev "$dev" parent "$classid" handle "$handle" 2>/dev/null || true
  tc qdisc add dev "$dev" parent "$classid" handle "$handle" netem delay "${delay}ms"

  # 5) filter mark -> class (idempotent)
  tc filter show dev "$dev" parent 1: 2>/dev/null | grep -q "handle $mark.*fw" \
    || tc filter add dev "$dev" parent 1: protocol ip prio 1 handle "$mark" fw flowid "$classid"

  echo "OK: $src -> $dst delay=${delay}ms (egress=$dev mark=$mark)"
}

remove_delay() {
  local src="$1" dst="$2"
  local dev mark classid handle

  dev="$(egress_dev "$dst")"
  [ -n "$dev" ] || { echo "ERROR: cannot find egress interface for dst=$dst" >&2; exit 1; }

  mark="$(mark_dir "$src" "$dst")"
  classid="1:${mark}"
  handle="${mark}:"

  # remove iptables mark rule(s)
  while iptables -t mangle -C FORWARD -s "$src" -d "$dst" -j MARK --set-mark "$mark" 2>/dev/null; do
    iptables -t mangle -D FORWARD -s "$src" -d "$dst" -j MARK --set-mark "$mark" || true
  done

  # remove netem qdisc for this direction if present
  tc qdisc del dev "$dev" parent "$classid" handle "$handle" 2>/dev/null || true

  echo "OK: removed $src -> $dst (egress=$dev mark=$mark)"
}

if [ "$CMD" = "set" ]; then
  apply_delay "$SRC" "$DST" "$DELAY"
elif [ "$CMD" = "del" ]; then
  remove_delay "$SRC" "$DST"
fi
'
gw "$gw_script"
