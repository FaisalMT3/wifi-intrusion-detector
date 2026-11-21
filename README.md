# Wi-Fi intrusion detector

A small sensor that listens to 802.11 management frames and raises an alert for three attacks on a wireless network, tested against real attack frames from an ESP8266 board on a home network.

| Alert | Attack | How it is recognised |
|---|---|---|
| `deauth_flood` | Forged deauthentication frames that knock clients off the network | Deauth activity involving one device in 5 or more separate tenths of a second within 5 seconds, or 60 or more deauth frames in that time |
| `rogue_ap` | Evil twin: another access point announcing your network name | A protected SSID, in any SSID field of the frame, announced by a BSSID that is not on the allowlist, including look-alike names |
| `beacon_flood` | Hundreds of fake networks to confuse users and scanners | 15 or more never-seen access points within 10 seconds |

## Results

Each scenario was run several times with the start and end of every attack recorded, so alerts could be scored against ground truth ([`lab/score.py`](lab/score.py)).

| Scenario | Runs | Detected | False alarms | Median time to alert |
|---|---|---|---|---|
| Deauth flood (15 frames in 3 s) | 6 | 6 | | 2.0 s |
| Evil twin of the protected SSID | 4 | 4 | | 0.9 s |
| Beacon flood (30 fake networks) | 4 | 4 | | 6.6 s |
| Stray deauth frames, one every 7 s (must stay quiet) | 3 | | 0 | |
| Two minutes with no attack (must stay quiet) | 1 | | 0 | |

The quiet period was not empty: 20 genuine deauth frames from the real access point were on the air in it, and the detector correctly ignored them.

These are the numbers for the final detector, replayed over the recorded capture of the second run. The first two versions did worse, and the reasons are the most useful part of the project.

## Three things the first versions got wrong

**1. It missed every evil twin (0 of 4).** The detector compared the announced name with the protected name byte for byte. The attack tool pads the name with spaces to 32 bytes, so `HomeLab` was announced as `HomeLab` followed by 25 spaces. On a phone the two are indistinguishable; to the detector they were different networks. Names are now compared the way a person sees them, with padding and invisible characters removed, and the alert says when a look-alike name was used. Replaying the first capture through the fixed code found all four.

**2. It raised a false alarm on every stray deauth frame (3 of 3).** The rule was "10 deauth frames in 5 seconds". In the capture, 864 of 961 deauth frames (90%) had the retry flag set. A frame that is not acknowledged is repeated by the radio about nine more times within milliseconds, so one frame on paper was ten on the air and a single stray frame reached the flood threshold.

**3. The obvious fix was also wrong.** Counting each sequence number once made the detector miss every flood (0 of 6), because the attack tool sends all its frames with the same sequence number. The final rule counts neither frames nor sequence numbers. It counts in how many separate tenths of a second deauth frames were heard: one frame with all its repeats fills one or two, a flood fills many.

Each fix was checked by replaying the saved capture, so the comparison is on identical packets and needs no second attack.

## Hardening against evasion

A detector is itself a target. Reviewing the rules for ways around them found three, each now closed and covered by a test in [`test_wids.py`](test_wids.py):

| Evasion | Fix |
|---|---|
| Put a different value in the BSSID field of every forged frame, so no single counter fills up | Count per sender and receiver address. A forged frame only works if those are real; the BSSID field can be anything |
| Send the whole burst inside one tenth of a second | A second threshold on raw frames (60 in 5 seconds), far above the ten or so copies of one retransmitted frame |
| Add a second, harmless SSID field after the real one, so a parser that keeps the last one sees the decoy | Every SSID field in the frame is checked against the protected names |

## What the attack does to a client

To show why this matters, the same deauth frames were aimed at a normally connected laptop for 31 seconds ([`lab/impact_test.sh`](lab/impact_test.sh), log in [results/impact/client-log.txt](results/impact/client-log.txt)).

| Time | Event on the client |
|---|---|
| 19:16:39 | Attack starts |
| 19:16:40 | Disconnected (`reason=1`), one second in |
| 19:16:42 to 19:16:45 | Reconnects twice and is thrown off again each time |
| 19:16:45 | An interrupted handshake is recorded as `WRONG_KEY` and the network is temporarily disabled |
| 19:17:10 | Attack ends |
| 19:18:45 | The system asks for the Wi-Fi password. Nobody is at the keyboard, so the connection is marked failed |
| 19:35:06 | Back online, only after the network service was restarted |

A 31-second attack caused an 18-minute outage. The interrupted handshake looked like a wrong password, and an unattended machine cannot answer a password prompt. For a headless device (a camera, a sensor, a payment terminal) that means offline until someone visits it.

The access point advertises RSN capabilities `0x000c`: management frame protection (802.11w) is neither required nor offered, which is why forged deauth frames are accepted.

## Run the sensor

Needs Python 3, scapy and a Wi-Fi card in monitor mode on the channel of the network to protect.

```bash
# 1. During a period you trust, learn which access points really serve your SSID
sudo python3 wids.py --iface wlan0mon --learn 60 --ssid MyNetwork > config.json

# 2. Watch
sudo python3 wids.py --iface wlan0mon --config config.json --out alerts.jsonl

# Or analyse a capture file
python3 wids.py --pcap capture.pcap --config config.json
```

Alerts are JSON lines:

```json
{"time": "2026-11-21T19:09:14", "alert": "rogue_ap", "severity": "high", "ssid": "HomeLab", "bssid": "02:de:ad:be:ef:00", "encryption": "open or legacy", "lookalike_name": true}
```

Thresholds are in the config file. `python3 test_wids.py` runs the detector against synthetic frames and needs no radio.

## The test rig

- **Attacker:** an ESP8266 NodeMCU running the open-source [esp8266_deauther](https://github.com/SpacehuhnTech/esp8266_deauther) firmware, driven over its serial console by [`lab/esp_attack.py`](lab/esp_attack.py).
- **Sensor:** a laptop's built-in Intel card in monitor mode.
- **Protocol:** [`lab/run_experiment.sh`](lab/run_experiment.sh) runs every scenario and writes the ground truth. The laptop's only network card is busy listening, so the machine is offline for the whole run and the script is started detached with a fail-safe timer that restores the connection.

Rules followed:

- Only my own network and my own devices. The driver reads the target from `lab/lab.json` and refuses the broadcast address, so it cannot be pointed at a whole network by accident.
- For the detection runs the target was a device that was not connected at the time, so nobody in the house lost their connection.
- The real-impact test disconnected one laptop, mine.

## Control mapping (NCA ECC-2:2024)

| Control | Relevance |
|---|---|
| 2-5-3-4 Wireless network security using secure authentication and encryption | The impact test shows what WPA2 without protected management frames allows. Fix: WPA3, or WPA2 with 802.11w required |
| 2-5-3-6 Intrusion Prevention Systems | Wired IDS sensors do not see these attacks. They exist only on the radio |
| 2-12-3-4 Continuous monitoring of cybersecurity event logs | Alerts are JSON lines that a SIEM can ingest |
| 2-13-3-1 Incident response plans | A deauth flood plus a twin of the corporate SSID is the first step of credential theft, and belongs in the playbook |

## Limits

- One channel at a time. An evil twin on another channel is not seen. A real deployment needs a dedicated adapter that hops channels.
- A twin that also copies the real access point's BSSID passes the allowlist. Catching that needs signal-strength or sequence-number tracking.
- A patient attacker who sends one deauth frame every few seconds stays under both flood thresholds and still disturbs a client. A per-client rule over a longer window would be the next addition.
- The allowlist is trust-on-first-use: whatever is on the air during `--learn` is believed.
- Tested against one attack tool on one network.
