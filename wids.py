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

BROADCAST = "ff:ff:ff:ff:ff:ff"
MAX_TRACKED = 5000          # addresses remembered for deauth counting
DEFAULTS = {
    "protected": {},            # SSID -> list of BSSIDs that are allowed to announce it
    "deauth_threshold": 5,      # tenths of a second with deauth frames for one BSSID ...
    "deauth_window": 5,         # ... inside this many seconds
    "deauth_frame_threshold": 60,   # or this many deauth frames in the window, however they are spaced
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
        self.deauths = collections.OrderedDict()                    # address -> deque of (time, tenth-of-second slot)
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
        # One deauth frame is rarely one frame on the air: if it is not acknowledged the radio repeats it
        # up to about ten times within a few milliseconds, and attack tools often reuse one sequence
        # number, so neither raw frames nor sequence numbers can be counted. What is counted instead is
        # the number of separate tenths of a second in which deauth frames were heard.
        #
        # The count is kept per address named in the frame: receiver, sender and BSSID. A forged frame
        # only works if receiver and sender are real, and a broadcast deauth has to carry the real
        # BSSID, so rotating any one field cannot spread a flood thinly enough to hide it.
        window = self.cfg["deauth_window"]
        parties = {a.lower() for a in (dot.addr1, dot.addr2, dot.addr3) if a} - {BROADCAST}
        worst = None
        for addr in parties:
            seen = self.deauths.setdefault(addr, collections.deque())
            self.deauths.move_to_end(addr)
            seen.append((now, int(now * 10)))
            while seen and now - seen[0][0] > window:
                seen.popleft()
            slots = len({slot for _, slot in seen})
            if worst is None or (slots, len(seen)) > worst[1:]:
                worst = (addr, slots, len(seen))
        while len(self.deauths) > MAX_TRACKED:      # hard limit: forged addresses push out the least recently seen
            self.deauths.popitem(last=False)
        if worst is None:
            return
        addr, slots, frames = worst
        # the second condition catches a burst squeezed into one or two slots: far more frames than
        # the ten or so copies of a single retransmitted frame
        if slots >= self.cfg["deauth_threshold"] or frames >= self.cfg["deauth_frame_threshold"]:
            if all(now - self.last_alert.get(("deauth_flood", a), -1e9) >= self.cfg["cooldown"] for a in parties):
                self.alert(now, "deauth_flood", addr, "high", bssid=(dot.addr3 or "").lower(),
                           addresses=sorted({a.lower() for a in (dot.addr1, dot.addr2) if a}),
                           active_tenths_of_second=slots, frames_on_air=frames, window_seconds=window)
                for a in parties:                # one alert per flood, whichever address it is counted on
                    self.last_alert[("deauth_flood", a)] = now

    def on_beacon(self, now, pkt, dot):
        bssid = (dot.addr3 or "").lower()
        names, has_rsn = [], False
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            if elt.ID == 0:
                names.append((elt.info or b"").decode("utf-8", "replace"))
            elif elt.ID == 48:
                has_rsn = True
            elt = elt.payload.getlayer(Dot11Elt)
        ssid = names[0] if names else ""
        # Clients read the first SSID element. A frame with a second one is not something a normal access
        # point sends, so every element is checked against the protected names, not only the last.
        for name in names:
            if normalise(name) in self.protected:
                ssid = name
                break
        shown = normalise(ssid)                 # what a person sees in the network list
        allowed = self.protected.get(shown)
        if allowed is not None and bssid not in allowed:
            lookalike = shown != ssid
            self.alert(now, "rogue_ap", (shown, bssid), "high", ssid=shown, bssid=bssid,
                       encryption="WPA2/WPA3" if has_rsn else "open or legacy", lookalike_name=lookalike,
                       ssid_elements=len(names),
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
