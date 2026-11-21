"""Run with: python3 test_wids.py   (needs scapy, no radio)"""
from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, RadioTap

from wids import Detector

AP, STA, FAKE = "aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02", "02:de:ad:be:ef:00"


def deauth(t, ap=AP, sta=STA, bssid=None):
    p = RadioTap() / Dot11(type=0, subtype=12, addr1=sta, addr2=ap, addr3=bssid or ap) / Dot11Deauth(reason=1)
    p.time = t
    return p


def beacon(t, bssid, ssid, rsn=True):
    p = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) \
        / Dot11Beacon() / Dot11Elt(ID=0, info=ssid.encode())
    if rsn:
        p = p / Dot11Elt(ID=48, info=b"\x01\x00")
    p.time = t
    return p


def run(frames, **cfg):
    alerts = []
    d = Detector({"protected": {"Home": [AP]}, "warmup": 0, **cfg}, alerts.append)
    for f in frames:
        d.handle(f)
    return alerts


# a flood fires once, then stays quiet during the cooldown
a = run([deauth(100 + i * 0.11) for i in range(40)])
assert [x["alert"] for x in a] == ["deauth_flood"] and a[0]["bssid"] == AP and a[0]["addresses"] == sorted([AP, STA]), a
# a forged BSSID field that changes on every frame does not split the count
assert len(run([deauth(100 + i * 0.11, bssid="02:00:00:00:00:%02x" % i) for i in range(40)])) == 1
# a flood spread over many clients of one access point still adds up on the access point
assert len(run([deauth(100 + i * 0.11, sta="bb:bb:bb:bb:bb:%02x" % i) for i in range(40)])) >= 1
# 80 frames squeezed into one tenth of a second are far more than one retransmitted frame
assert len(run([deauth(100.001 + i * 0.001) for i in range(80)])) == 1
# the odd deauth of normal roaming does not fire
assert run([deauth(100 + i * 3) for i in range(9)]) == []
# deauth activity in 4 separate tenths of a second is below the threshold of 5; the 5th fires
assert run([deauth(100 + i * 0.25) for i in range(4)]) == []
assert len(run([deauth(100 + i * 0.25) for i in range(5)])) == 1
# one frame repeated 9 times by the radio within a few milliseconds is one event, not a flood
assert run([deauth(100.01 + i * 0.004) for i in range(10)]) == []
# and the same every 7 seconds, as when devices roam, stays quiet
assert run([deauth(100.01 + burst * 7 + i * 0.004) for burst in range(5) for i in range(10)]) == []
# the real access point is fine, a twin is not, and an open twin is reported as such
assert run([beacon(1, AP, "Home")]) == []
a = run([beacon(1, FAKE, "Home", rsn=False)])
assert a[0]["alert"] == "rogue_ap" and a[0]["bssid"] == FAKE and a[0]["encryption"] == "open or legacy", a
assert run([beacon(1, FAKE, "Neighbour")]) == []
# a twin whose name is padded with spaces or NULs looks identical on a phone and must still be caught
for padded in ("Home" + " " * 28, "Home\x00\x00", " Home"):
    a = run([beacon(1, FAKE, padded)])
    assert a and a[0]["alert"] == "rogue_ap" and a[0]["ssid"] == "Home" and a[0]["lookalike_name"], (padded, a)
assert run([beacon(1, AP, "Home" + " " * 28)]) == []        # the real access point may pad its own name
# a twin that hides the protected name in the first SSID element and adds a decoy second one
two = beacon(1, FAKE, "Home") / Dot11Elt(ID=0, info=b"Neighbour")
a = run([two])
assert a and a[0]["alert"] == "rogue_ap" and a[0]["ssid"] == "Home" and a[0]["ssid_elements"] == 2, a
# many never-seen access points in a short time is a beacon flood; the same ones again are not
flood = [beacon(10 + i * 0.1, "02:00:00:00:00:%02x" % i, "free%d" % i) for i in range(20)]
a = run(flood)
assert [x["alert"] for x in a] == ["beacon_flood"], a
assert run([beacon(10 + i * 60, "02:00:00:00:00:%02x" % i, "n%d" % i) for i in range(20)]) == []
# access points heard during warm-up are the neighbourhood, not a flood
assert run(flood, warmup=60) == []
# a new alert is allowed after the cooldown
assert len(run([deauth(100 + i * 0.11) for i in range(20)] + [deauth(200 + i * 0.11) for i in range(20)])) == 2
print("OK")
