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

gw() { docker exec -u 0 "$GW" sh -lc "$1"; }
cx() { docker exec -u 0 "$1" sh -lc "$2"; }

need_docker() {
  command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 1; }
  docker ps --format '{{.Names}}' | grep -qx "$GW" || { echo "Gateway '$GW' not running"; exit 1; }
}
need_docker

find_container_by_ip() {
  local ip="$1" c
  for c in $(docker ps --format '{{.Names}}' | grep -E "^${PREFIX}" || true); do
    if docker inspect "$c" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
      | tr ' ' '\n' | grep -Fxq "$ip"; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

pick_tc_container() {
  local c="$1"
  docker ps --format '{{.Names}}' | grep -qx "${c}-route" && echo "${c}-route" || echo "$c"
}

[ $# -ge 1 ] || usage
cmd="$1"; shift

case "$cmd" in
  set)  [ $# -eq 3 ] || usage; SRC="$1"; DST="$2"; DELAY="$3" ;;
  del)  [ $# -eq 2 ] || usage; SRC="$1"; DST="$2" ;;
  list) [ $# -eq 0 ] || usage ;;
  *) usage ;;
esac

if [ "$cmd" = "list" ]; then
  for c in $(docker ps --format '{{.Names}}' | grep -E "^${PREFIX}" || true); do
    ips="$(docker inspect "$c" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' | xargs)"
    echo "--- $c ($ips)"
    cx "$c" '
      command -v tc >/dev/null 2>&1 || exit 0
      for d in $(ls /sys/class/net | grep -E "^eth"); do
        echo "dev=$d"
        tc qdisc show dev "$d" || true
        tc class show dev "$d" 2>/dev/null || true
        tc filter show dev "$d" parent 1: 2>/dev/null || true
      done
      echo
    ' || true
  done
  exit 0
fi

SRC_CONTAINER="$(find_container_by_ip "$SRC" || true)"
[ -n "$SRC_CONTAINER" ] || { echo "ERROR: could not find container with SRC IP $SRC"; exit 1; }
TC_CONTAINER="$(pick_tc_container "$SRC_CONTAINER")"

tc_script='
set -euo pipefail
CMD="'"$cmd"'"
SRC="'"${SRC:-}"'"
DST="'"${DST:-}"'"
DELAY="'"${DELAY:-}"'"

egress_dev() {
  ip route get "$1" 2>/dev/null | awk "{for(i=1;i<=NF;i++) if(\$i==\"dev\"){print \$(i+1); exit}}"
}

mark_dir() {
  local x
  x=$(printf "%s->%s" "$1" "$2" | cksum | awk "{print \$1}")
  echo $(( (x % 4095) + 1 ))
}

ensure_root_htb() {
  local dev="$1"
  if ! tc qdisc show dev "$dev" | grep -q "htb 1:"; then
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

  ensure_root_htb "$dev"

  tc class show dev "$dev" 2>/dev/null | grep -q "class htb $classid" \
    || tc class add dev "$dev" parent 1: classid "$classid" htb rate 1000mbit ceil 1000mbit quantum 125000

  tc qdisc del dev "$dev" parent "$classid" handle "$handle" 2>/dev/null || true
  tc qdisc add dev "$dev" parent "$classid" handle "$handle" netem delay "${delay}ms"

  tc filter del dev "$dev" parent 1: protocol ip prio "$mark" u32 2>/dev/null || true
  tc filter add dev "$dev" parent 1: protocol ip prio "$mark" u32 \
    match ip dst "$dst"/32 \
    flowid "$classid"

  echo "OK: $src -> $dst delay=${delay}ms"
}

remove_delay() {
  local src="$1" dst="$2"
  local dev mark classid handle

  dev="$(egress_dev "$dst")"
  [ -n "$dev" ] || { echo "ERROR: cannot find egress interface for dst=$dst" >&2; exit 1; }

  mark="$(mark_dir "$src" "$dst")"
  classid="1:${mark}"
  handle="${mark}:"

  tc filter del dev "$dev" parent 1: protocol ip prio "$mark" u32 2>/dev/null || true
  tc qdisc del dev "$dev" parent "$classid" handle "$handle" 2>/dev/null || true
  tc class del dev "$dev" classid "$classid" 2>/dev/null || true

  echo "OK: removed $src -> $dst"
}

if [ "$CMD" = "set" ]; then
  apply_delay "$SRC" "$DST" "$DELAY"
else
  remove_delay "$SRC" "$DST"
fi
'

cx "$TC_CONTAINER" "$tc_script"