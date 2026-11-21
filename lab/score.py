#!/usr/bin/env python3
"""Compare the detector's alerts with the ground truth written by run_experiment.sh.

    python3 score.py runs/<run>/ground_truth.jsonl runs/<run>/alerts.jsonl

A scenario run counts as detected if an alert of the expected kind fires
between its start and five seconds after its end. An alert that falls in no
attack window, or is of the wrong kind for its window, is a false positive.
"""
import json
import statistics
import sys

EXPECT = {"deauth_flood": "deauth_flood", "rogue_ap": "rogue_ap", "beacon_flood": "beacon_flood",
          "deauth_low_rate": None, "baseline": None}      # None = must stay silent


def load(path):
    return [json.loads(line) for line in open(path) if line.strip()]


def score(truth, alerts):
    marks = load(truth) if isinstance(truth, str) else truth
    alerts = load(alerts) if isinstance(alerts, str) else alerts
    windows = [(marks[i]["scenario"], marks[i]["epoch"], marks[i + 1]["epoch"]) for i in range(0, len(marks) - 1, 2)]
    table, used = {}, set()
    for name, start, end in windows:                         # first hand every alert to the attack it belongs to
        row = table.setdefault(name, {"runs": 0, "detected": 0, "latency": [], "unexpected_alerts": 0})
        row["runs"] += 1
        hits = [i for i, a in enumerate(alerts) if a["alert"] == EXPECT[name] and start <= a["epoch"] <= end + 5 and i not in used]
        if hits:
            row["detected"] += 1
            row["latency"].append(alerts[hits[0]]["epoch"] - start)
            used.update(hits)
    for name, start, end in windows:                         # whatever is left inside a window should not be there
        table[name]["unexpected_alerts"] += sum(1 for i, a in enumerate(alerts) if i not in used and start <= a["epoch"] <= end)
    stray = [a for i, a in enumerate(alerts) if i not in used and not any(s <= a["epoch"] <= e for _, s, e in windows)]
    for row in table.values():
        row["median_latency_s"] = round(statistics.median(row.pop("latency")), 1) if row["latency"] else None
    return {"scenarios": table, "alerts_outside_any_window": len(stray), "total_alerts": len(alerts)}


if __name__ == "__main__":
    result = score(sys.argv[1], sys.argv[2])
    print(json.dumps(result, indent=1))
