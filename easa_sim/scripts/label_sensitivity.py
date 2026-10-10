#!/usr/bin/env python3
"""Sensitivity of the dominant-source labelling rule to its thresholds (review round 2, R3).

  python scripts/label_sensitivity.py --config config/default.yaml --out results/label_sensitivity.csv

For a grid of (min_share, max_attackers, weak_threshold) the attacker set of every attack type is recomputed from the
raw CSVs (one pass over Src IP and packet counts; the default setting is read from the cache), and for each setting the
script reports, per attack type: the attacker set, Jaccard overlap with the default set, whether the type is dropped as
weak, and the share of flows whose row label changes relative to the default rule (flows with the changed addresses as
source or destination). This is a rule-sensitivity audit, not a ground-truth audit: it says how much the labels depend
on the thresholds, not whether the designated addresses are the attackers.
"""
import argparse
import itertools
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from easa.config import load_config  # noqa: E402
from easa.data.iotdiad import attacker_sets, catalogue, read_csv_canon, BENIGN  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/default.yaml")
    ap.add_argument("--out", default="results/label_sensitivity.csv")
    ap.add_argument("--min_share", nargs="*", type=float, default=[0.03, 0.05, 0.10])
    ap.add_argument("--max_attackers", nargs="*", type=int, default=[6, 8, 12])
    ap.add_argument("--weak", nargs="*", type=float, default=[0.30, 0.40, 0.50])
    a = ap.parse_args()
    cfg = load_config(a.config); d = cfg["data"]
    root = d["iotdiad_dir"]; subnet = d.get("iotdiad_subnet", "192.168.137.0/24"); excl = set(d.get("iotdiad_exclude_ips", []))
    pkt_types = tuple(d.get("iotdiad_packet_share_types", ["ICMP", "Mirai"]))
    cat = catalogue(root, int(d.get("iotdiad_min_rows", 100)))
    default = (float(d.get("iotdiad_min_share", 0.05)), int(d.get("iotdiad_max_attackers", 8)), float(d.get("iotdiad_weak_threshold", 0.40)))
    base = attacker_sets(root, cat, subnet, excl, *default, cache=os.path.join(root, "iotdiad_attackers.json"), pkt_types=pkt_types)
    # endpoint pairs per attack type (one pass) to measure how many flows change label
    pairs = {}
    for e in cat:
        if e["family"] == BENIGN: continue
        df = read_csv_canon(e["path"], usecols=["Src IP", "Dst IP"])
        pairs.setdefault(e["attack"], []).append(df)
    pairs = {k: pd.concat(v, ignore_index=True) for k, v in pairs.items()}
    rows = []
    for ms, ma, wk in itertools.product(a.min_share, a.max_attackers, a.weak):
        alt = attacker_sets(root, cat, subnet, excl, ms, ma, wk, cache=None, pkt_types=pkt_types)
        for attack, b in base.items():
            A, B = set(b["attackers"]), set(alt[attack]["attackers"])
            df = pairs[attack]
            lab_a = df["Src IP"].isin(A) | df["Dst IP"].isin(A)
            lab_b = df["Src IP"].isin(B) | df["Dst IP"].isin(B)
            rows.append({"min_share": ms, "max_attackers": ma, "weak_threshold": wk, "attack": attack,
                         "default_weak": b["weak"], "alt_weak": alt[attack]["weak"],
                         "n_default": len(A), "n_alt": len(B), "jaccard": len(A & B) / max(1, len(A | B)),
                         "flows": len(df), "label_changed_frac": float((lab_a != lab_b).mean()),
                         "attack_frac_default": float(lab_a.mean()), "attack_frac_alt": float(lab_b.mean()),
                         "alt_attackers": " ".join(sorted(B))})
        print(f"min_share={ms} max={ma} weak={wk}: mean Jaccard {np.mean([r['jaccard'] for r in rows[-len(base):]]):.2f}, "
              f"mean label change {np.mean([r['label_changed_frac'] for r in rows[-len(base):]]):.3f}")
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    pd.DataFrame(rows).to_csv(a.out, index=False); print("saved ->", a.out)


if __name__ == "__main__":
    main()
