#!/usr/bin/env python3
"""wids: a small wireless intrusion detector for 802.11 management-frame attacks.

Watches a monitor-mode interface (or reads a capture file) and raises alerts for
  deauth_flood   many deauthentication/disassociation frames for one network
  rogue_ap       a protected SSID announced by an access point that is not on the allowlist
  beacon_flood   a burst of access points never seen before

    sudo python3 wids.py --iface mon0 --config config.json
    python3 wids.py --pcap capture.pcap --config config.json
    sudo python3 wids.py --iface mon0 --learn 60 --ssid MyNetwork > config.json
"""
import argparse
import collections
import json
import sys
import time

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, PcapReader, sniff

DEFAULTS = {
    "protected": {},            # SSID -> list of BSSIDs that are allowed to announce it
    "deauth_threshold": 5,      # tenths of a second with deauth frames for one BSSID ...
    "deauth_window": 5,         # ... inside this many seconds
    "beacon_flood_threshold": 15,   # access points never seen before ...
    "beacon_flood_window": 10,      # ... inside this many seconds
    "warmup": 60,               # seconds at start-up spent learning which access points are already around
    "cooldown": 30,             # seconds before the same alert may fire again
}


def normalise(ssid):
    """Strip what a phone or laptop does not show: padding spaces, NULs and other control characters.

    An evil twin does not need the exact bytes of the real name, only a name that looks the same.
    """
    return "".join(ch for ch in ssid if ch.isprintable()).strip()


class Detector:
    """Feed it frames with handle(); alerts come out of the emit callback."""

    def __init__(self, config, emit):
        self.cfg = {**DEFAULTS, **config}
        self.protected = {s: {b.lower() for b in bs} for s, bs in self.cfg["protected"].items()}
        self.emit = emit
        self.deauths = collections.defaultdict(collections.deque)   # bssid -> (time, frame identity)
        self.targets = collections.defaultdict(set)                 # bssid -> stations named in the frames
        self.known_aps = set()                                      # every BSSID seen in a beacon
        self.new_aps = collections.deque()                          # (time, bssid, ssid) of first sightings
        self.last_alert = {}
        self.started = None                                         # time of the first frame

    def alert(self, now, kind, key, severity, **details):
        if now - self.last_alert.get((kind, key), -1e9) < self.cfg["cooldown"]:
            return
        self.last_alert[(kind, key)] = now
        self.emit({"time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)), "epoch": round(now, 3),
                   "alert": kind, "severity": severity, **details})

    def handle(self, pkt):
        if not pkt.haslayer(Dot11) or pkt.type != 0:        # management frames only
            return
        now, dot = float(pkt.time), pkt[Dot11]
        if self.started is None:
            self.started = now
        if dot.subtype in (10, 12):                         # disassociation, deauthentication
            self.on_deauth(now, dot)
        elif pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            self.on_beacon(now, pkt, dot)

    def on_deauth(self, now, dot):
        bssid = (dot.addr3 or "").lower()
        # One deauth frame is rarely one frame on the air: if it is not acknowledged the radio repeats it
        # up to about ten times within a few milliseconds, and attack tools often reuse one sequence
        # number, so neither raw frames nor sequence numbers can be counted. What is counted instead is
        # the number of separate tenths of a second in which deauth frames for this network were heard.
        seen = self.deauths[bssid]
        seen.append((now, int(now * 10)))
        while seen and now - seen[0][0] > self.cfg["deauth_window"]:
            seen.popleft()
        distinct = len({slot for _, slot in seen})
        self.targets[bssid].update(a.lower() for a in (dot.addr1, dot.addr2) if a and a.lower() != bssid)
        if distinct >= self.cfg["deauth_threshold"]:
            self.alert(now, "deauth_flood", bssid, "high", bssid=bssid, active_tenths_of_second=distinct,
                       frames_on_air=len(seen),
                       window_seconds=self.cfg["deauth_window"], stations=sorted(self.targets[bssid])[:10])
            self.targets[bssid].clear()

    def on_beacon(self, now, pkt, dot):
        bssid = (dot.addr3 or "").lower()
        ssid, has_rsn = "", False
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            if elt.ID == 0:
                ssid = (elt.info or b"").decode("utf-8", "replace")
            elif elt.ID == 48:
                has_rsn = True
            elt = elt.payload.getlayer(Dot11Elt)
        shown = normalise(ssid)                 # what a person sees in the network list
        allowed = self.protected.get(shown)
        if allowed is not None and bssid not in allowed:
            lookalike = shown != ssid
            self.alert(now, "rogue_ap", (shown, bssid), "high", ssid=shown, bssid=bssid,
                       encryption="WPA2/WPA3" if has_rsn else "open or legacy", lookalike_name=lookalike,
                       note="protected SSID announced by an access point that is not on the allowlist"
                            + (" (name padded with invisible characters)" if lookalike else ""))
        if bssid in self.known_aps:
            return
        self.known_aps.add(bssid)
        if now - self.started < self.cfg["warmup"]:     # the neighbourhood is not a flood
            return
        self.new_aps.append((now, bssid, ssid))
        while self.new_aps and now - self.new_aps[0][0] > self.cfg["beacon_flood_window"]:
            self.new_aps.popleft()
        if len(self.new_aps) >= self.cfg["beacon_flood_threshold"]:
            self.alert(now, "beacon_flood", "all", "medium", new_access_points=len(self.new_aps),
                       window_seconds=self.cfg["beacon_flood_window"],
                       sample_ssids=sorted({s for _, _, s in self.new_aps if s})[:8])


def learn(iface, seconds, ssids):
    """Listen for a trusted period and print a config that allowlists what was heard."""
    seen = collections.defaultdict(set)

    def note(pkt):
        if pkt.haslayer(Dot11Beacon):
            elt = pkt.getlayer(Dot11Elt)
            if elt is not None and elt.ID == 0:
                name = (elt.info or b"").decode("utf-8", "replace")
                if name in ssids:
                    seen[name].add(pkt[Dot11].addr3.lower())

    sniff(iface=iface, prn=note, store=False, timeout=seconds)
    print(json.dumps({**DEFAULTS, "protected": {s: sorted(seen[s]) for s in ssids}}, indent=1))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="monitor-mode interface to listen on")
    src.add_argument("--pcap", help="capture file to analyse instead of a live interface")
    ap.add_argument("--config", help="JSON file with the allowlist and thresholds")
    ap.add_argument("--out", help="append alerts to this file as JSON lines")
    ap.add_argument("--learn", type=int, metavar="SECONDS", help="build a config from what is on the air now")
    ap.add_argument("--ssid", action="append", default=[], help="SSID to protect (with --learn)")
    a = ap.parse_args()

    if a.learn:
        return learn(a.iface, a.learn, set(a.ssid))
    config = json.load(open(a.config)) if a.config else {}
    out = open(a.out, "a", buffering=1) if a.out else None

    def emit(alert):
        line = json.dumps(alert, ensure_ascii=False)
        print(line, flush=True)
        if out:
            out.write(line + "\n")

    det = Detector(config, emit)
    if a.pcap:
        with PcapReader(a.pcap) as reader:
            for pkt in reader:
                det.handle(pkt)
    else:
        sniff(iface=a.iface, prn=det.handle, store=False)


if __name__ == "__main__":
    sys.exit(main())
