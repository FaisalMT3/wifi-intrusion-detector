#!/usr/bin/env python3
"""Lab driver for an ESP8266 running the open-source esp8266_deauther firmware.

Sends test frames over the board's serial console so the detector can be
measured against a known ground truth. It only works against the networks and
stations listed in lab.json, and never against the broadcast address.

    python3 esp_attack.py deauth --count 15 --rate 5 --frames 25
    python3 esp_attack.py eviltwin --seconds 15
    python3 esp_attack.py beaconflood --count 40
"""
import argparse
import json
import os
import random
import sys
import time

import serial

LAB = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab.json")))


def console():
    """Open the serial console without pulsing DTR/RTS, which would reboot the board."""
    s = serial.Serial()
    s.port, s.baudrate, s.timeout = LAB["port"], 115200, 0.2
    s.dtr = s.rts = False
    s.open()
    time.sleep(0.3)
    s.reset_input_buffer()
    send(s, "stop all")
    return s


def send(s, command):
    s.write(command.encode() + b"\r\n")
    s.flush()
    return s.read(300).decode(errors="replace")


def deauth(s, count, rate, frames):
    """Each command makes the board send a burst of `frames` deauthentication frames."""
    ap, sta = LAB["own_bssid"].lower(), LAB["own_station"].lower()
    if sta == "ff:ff:ff:ff:ff:ff":
        sys.exit("refusing to deauthenticate the broadcast address")
    send(s, f"set deauthspertarget {frames}")
    for _ in range(count):
        t = time.time()
        send(s, f"send deauth {ap} {sta} 1 {LAB['channel']}")
        time.sleep(max(0, 1 / rate - (time.time() - t)))


def eviltwin(s, seconds):
    """Announce the lab SSID from a made-up access point without encryption."""
    end = time.time() + seconds
    while time.time() < end:
        send(s, f"send beacon {LAB['twin_bssid']} \"{LAB['own_ssid']}\" {LAB['channel']}")
        time.sleep(0.1)


def beaconflood(s, count):
    """Announce many networks that do not exist."""
    for i in range(count):
        mac = "02:" + ":".join("%02x" % random.randrange(256) for _ in range(5))
        send(s, f"send beacon {mac} \"FreeWiFi-{i:02d}\" {LAB['channel']} wpa2")
        time.sleep(0.1)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("scenario", choices=["deauth", "eviltwin", "beaconflood"])
    ap.add_argument("--count", type=int, default=40)
    ap.add_argument("--rate", type=float, default=5, help="commands per second (deauth)")
    ap.add_argument("--frames", type=int, default=25, help="frames per command (deauth)")
    ap.add_argument("--seconds", type=int, default=15)
    a = ap.parse_args()
    s = console()
    if a.scenario == "deauth":
        deauth(s, a.count, a.rate, a.frames)
    elif a.scenario == "eviltwin":
        eviltwin(s, a.seconds)
    else:
        beaconflood(s, a.count)


if __name__ == "__main__":
    main()
