#!/bin/bash
# Runs every test scenario against the detector and records ground truth.
#
# The Wi-Fi card goes into monitor mode, so the machine is OFFLINE while this
# runs. Start it detached (systemd-run or tmux), not from an SSH session:
#   sudo systemd-run --unit wids-lab /path/to/lab/run_experiment.sh wlp0s20f3
# The connection is restored at the end, on any error, and by run_failsafe.
set -u
IF=${1:?usage: run_experiment.sh <wifi-interface>}
HERE=$(cd "$(dirname "$0")/.." && pwd)
CH=$(python3 -c "import json;print(json.load(open('$HERE/lab/lab.json'))['channel'])")
SSID=$(python3 -c "import json;print(json.load(open('$HERE/lab/lab.json'))['own_ssid'])")
OUT=$HERE/runs/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"; cd "$HERE"

restore() {
  pkill -f "wids.py --iface" ; pkill -x tcpdump
  ip link set "$IF" down; iw dev "$IF" set type managed; ip link set "$IF" up
  nmcli device set "$IF" managed yes; sleep 2; nmcli device connect "$IF"
}
trap restore EXIT
mark() { echo "{\"epoch\": $(date +%s.%N), \"event\": \"$1\", \"scenario\": \"$2\"}" >> "$OUT/ground_truth.jsonl"; }

nmcli device set "$IF" managed no
ip link set "$IF" down; iw dev "$IF" set type monitor; ip link set "$IF" up; iw dev "$IF" set channel "$CH"

# 1. trusted period: learn which access points really serve the protected SSID
python3 wids.py --iface "$IF" --learn 30 --ssid "$SSID" > "$OUT/config.json"

tcpdump -i "$IF" -w "$OUT/capture.pcap" 'type mgt' 2>/dev/null &
python3 wids.py --iface "$IF" --config "$OUT/config.json" --out "$OUT/alerts.jsonl" > "$OUT/sensor.log" 2>&1 &
sleep 5

# 2. nothing happening: any alert here is a false positive (also covers the warm-up)
mark start baseline; sleep 120; mark end baseline

# 3. deauthentication flood: 15 bursts of 25 frames in about 3 seconds
for i in 1 2 3 4 5 6; do
  mark start deauth_flood; python3 lab/esp_attack.py deauth --count 15 --rate 5 --frames 25; mark end deauth_flood; sleep 35
done
# 4. a few stray deauth frames, as in normal roaming: must NOT alert
for i in 1 2 3; do
  mark start deauth_low_rate; python3 lab/esp_attack.py deauth --count 4 --rate 0.15 --frames 2; mark end deauth_low_rate; sleep 10
done
# 5. evil twin of the protected SSID
for i in 1 2 3 4; do
  mark start rogue_ap; python3 lab/esp_attack.py eviltwin --seconds 10; mark end rogue_ap; sleep 35
done
# 6. beacon flood
for i in 1 2 3 4; do
  mark start beacon_flood; python3 lab/esp_attack.py beaconflood --count 30; mark end beacon_flood; sleep 35
done
sleep 3
