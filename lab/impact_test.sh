#!/bin/bash
# Shows what a deauthentication attack does to a normally connected client.
# Run it while the Wi-Fi card is CONNECTED to the lab network (own_station in
# lab.json must be this machine's MAC). The link drops while it runs, so start
# it detached. Output: runs/impact-<time>/
set -u
IF=${1:?usage: impact_test.sh <wifi-interface>}
HERE=$(cd "$(dirname "$0")/.." && pwd)
GW=$(ip route | awk '/default/{print $3; exit}')
OUT=$HERE/runs/impact-$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"; cd "$HERE"
START=$(date '+%Y-%m-%d %H:%M:%S')
iw dev "$IF" link > "$OUT/link-before.txt"
ping -D -i 0.5 -W 1 "$GW" > "$OUT/ping.log" 2>&1 &
PING=$!
sleep 20                                                   # 20 s of normal traffic
date +%s.%N > "$OUT/attack-start.txt"
python3 lab/esp_attack.py deauth --count 60 --rate 2 --frames 25   # about 30 s of attack
date +%s.%N > "$OUT/attack-end.txt"
sleep 40                                                   # recovery
kill -INT $PING; sleep 1
journalctl -u wpa_supplicant -u NetworkManager --since "$START" --no-pager \
  | grep -iE 'deauth|disconnect|CTRL-EVENT|reason|associat|state change' > "$OUT/supplicant-events.txt"
iw dev "$IF" link > "$OUT/link-after.txt"
