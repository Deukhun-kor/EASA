#!/usr/bin/env python3
"""Non-circular check of the dominant-source rule on TON_IoT (revision r1, A2 of the internal review).

  python scripts/toniot_label_matrix.py --config config/v4_toniot.yaml --out results/v4/toniot_label_matrix.json

Three comparisons, all on the full mixed sample of the configured files (normal + attack rows, before any hygiene):
  1. host level: the rule's designated attacker set A (chosen from the attack-type blocks, as in the protocol) against
     the attacker hosts documented by the dataset authors (the Kali machines, last octet 30-39), and the normal /
     attack row counts of every designated host;
  2. row level, rule applied to EVERY row (src or dst in A => attack): TP / FP / TN / FN against the dataset label,
     i.e. including the false positives the rule would produce on normal traffic;
  3. row level, rule applied within the attack-type windows only (the protocol's use): the same matrix, where normal
     rows are benign by construction, so FP counts only attack-window rows outside the truth label (none in TON_IoT,
     whose window rows are all labelled attack) and the informative figure is FN.
"""
import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from easa.config import load_config  # noqa: E402
from easa.data.toniot import TYPE_MAP, _network_files, _read_network, dominant_src_sets  # noqa: E402

DOCUMENTED_LAST_OCTETS = set(range(30, 40))     # research.unsw.edu.au/projects/toniot-datasets: Kali hosts .30-.39


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--config", default="config/v4_toniot.yaml"); ap.add_argument("--out", default="results/v4/toniot_label_matrix.json")
    a = ap.parse_args()
    cfg = load_config(a.config); d = cfg["data"]
    df = _read_network(_network_files(d), int(d.get("toniot_max_rows_per_block", 0)))
    atype = df["type"].astype(str).str.lower().to_numpy()
    keep = np.array([TYPE_MAP.get(t, "Other") != "Other" for t in atype]); df = df[keep].reset_index(drop=True); atype = atype[keep]
    src, dst = df["src_ip"].astype(str).to_numpy(), df["dst_ip"].astype(str).to_numpy()
    y = pd.to_numeric(df["label"], errors="coerce").fillna(0).to_numpy(dtype=int)
    is_att_win = atype != "normal"
    rule = dominant_src_sets(src, atype, is_att_win, float(d.get("iotdiad_min_share", 0.05)), int(d.get("iotdiad_max_attackers", 8)),
                             float(d.get("iotdiad_weak_threshold", 0.40)), set(d.get("toniot_exclude_ips", [])))
    A = sorted({ip for v in rule.values() for ip in v["attackers"]})
    def last(ip):
        try: return int(ip.split(".")[-1])
        except Exception: return -1
    D = {ip for ip in set(src) | set(dst) if ip.startswith("192.168.1.") and last(ip) in DOCUMENTED_LAST_OCTETS}
    hosts = {}
    for ip in A:
        m = (src == ip) | (dst == ip)
        hosts[ip] = {"documented_attacker": last(ip) in DOCUMENTED_LAST_OCTETS, "normal_rows": int((m & ~is_att_win).sum()),
                     "attack_rows": int((m & is_att_win).sum()), "as_source_attack_rows": int(((src == ip) & is_att_win).sum()),
                     "designated_for": sorted(t for t, v in rule.items() if ip in v["attackers"])}
    inA = np.isin(src, A) | np.isin(dst, A)
    def cm(pred, truth):
        tp = int((pred & truth).sum()); fp = int((pred & ~truth).sum()); fn = int((~pred & truth).sum()); tn = int((~pred & ~truth).sum())
        return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": round(tp / max(1, tp + fp), 4), "recall": round(tp / max(1, tp + fn), 4),
                "fpr": round(fp / max(1, fp + tn), 4)}
    truth = y == 1
    out = {"files": [os.path.basename(f) for f in _network_files(d)], "rows": int(len(df)), "normal_rows": int((~is_att_win).sum()), "attack_rows": int(is_att_win.sum()),
           "designated_hosts": hosts, "documented_hosts_present": sorted(D),
           "host_level": {"n_designated": len(A), "n_documented_present": len(D), "designated_and_documented": len(set(A) & D),
                          "precision_vs_documented": round(len(set(A) & D) / max(1, len(A)), 4), "recall_vs_documented": round(len(set(A) & D) / max(1, len(D)), 4),
                          "designated_not_documented": sorted(set(A) - D), "documented_not_designated": sorted(D - set(A))},
           "row_level_rule_on_all_rows": cm(inA, truth),
           "row_level_rule_within_attack_windows": cm(inA & is_att_win, truth),
           "normal_rows_involving_designated_hosts_by_host": {ip: hosts[ip]["normal_rows"] for ip in A}}
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f: json.dump(out, f, indent=1)
    print(json.dumps({k: out[k] for k in ("rows", "normal_rows", "attack_rows", "host_level", "row_level_rule_on_all_rows", "row_level_rule_within_attack_windows")}, indent=1))
    print("designated hosts:"); print(pd.DataFrame(hosts).T.to_string()); print("saved ->", a.out)


if __name__ == "__main__":
    main()
