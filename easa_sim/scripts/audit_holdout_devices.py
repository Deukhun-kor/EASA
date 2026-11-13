#!/usr/bin/env python3
"""Metrics split by federation-wide held-out devices vs. devices seen in training (revision r1, editor point 2).

  python scripts/audit_holdout_devices.py results/traces/v4_holdout --results results/v4/v4_holdout.csv --out results/v4/v4_holdout_split.csv

For every run (config, seed) with saved traces, computes on the two device groups separately: FPR on clean devices
(share of their non-attacking epochs at level >= L2, devices never compromised in the run), restricted share of all
benign epochs, recall at L2 over attacking epochs, F1 at L2, and the false-quarantine rate (clean devices reaching L3).
The held-out devices are read from the `global_holdout_device_ids` column of the result CSV. Writes one row per
(config, seed, group) and prints the mean over seeds per (config, group) with a paired test held-out vs. seen.
"""
import argparse
import glob
import os

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon


def metrics(df: pd.DataFrame) -> dict:
    att = df["attacking"].astype(bool).to_numpy(); lv = df["level"].to_numpy(); pos = lv >= 2
    ever = df.groupby("device")["attacking"].transform("max").astype(bool).to_numpy()
    clean = ~ever
    # same convention as easa/metrics.py: negatives (FP, TN) are the epochs of devices never compromised in the run
    tp = int((att & pos).sum()); fp = int((clean & pos).sum()); fn = int((att & ~pos).sum())
    prec = tp / (tp + fp) if tp + fp else float("nan"); rec = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else float("nan")
    fq = df[clean].groupby("device")["level"].max().ge(3).mean() if clean.any() else float("nan")
    return {"n_devices": int(df["device"].nunique()), "n_clean_devices": int(df.loc[clean, "device"].nunique()),
            "fpr_L2": float(pos[clean & ~att].mean()) if (clean & ~att).any() else float("nan"),
            "restricted_share_benign": float(pos[~att].mean()) if (~att).any() else float("nan"),
            "recall_L2": rec, "f1_L2": f1, "false_quarantine_rate": float(fq)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("traces_dir"); ap.add_argument("--results", required=True); ap.add_argument("--out", default="results/v4/v4_holdout_split.csv")
    a = ap.parse_args()
    res = pd.read_csv(a.results)
    held = {}
    for _, r in res.iterrows():
        ids = str(r.get("global_holdout_device_ids", "") or "")
        held[(r["config"], int(r["seed"]))] = set(x for x in ids.split(";") if x and x != "nan")
    rows = []
    for f in sorted(glob.glob(os.path.join(a.traces_dir, "*_seed*.parquet")) + glob.glob(os.path.join(a.traces_dir, "*_seed*.csv.gz"))):
        base = os.path.basename(f); cfg = base.split("_seed")[0]; seed = int(base.split("_seed")[1].split(".")[0])
        if (cfg, seed) not in held or not held[(cfg, seed)]:
            continue
        df = pd.read_parquet(f) if f.endswith(".parquet") else pd.read_csv(f)
        h = held[(cfg, seed)]
        for group, sub in (("held-out", df[df["device"].isin(h)]), ("seen", df[~df["device"].isin(h)])):
            m = metrics(sub); m.update({"config": cfg, "seed": seed, "group": group}); rows.append(m)
    d = pd.DataFrame(rows); d.to_csv(a.out, index=False)
    pd.set_option("display.width", 220)
    cols = ["n_devices", "n_clean_devices", "fpr_L2", "restricted_share_benign", "recall_L2", "f1_L2", "false_quarantine_rate"]
    print(d.groupby(["config", "group"])[cols].mean().round(3).to_string())
    for cfg, g in d.groupby("config"):
        a_ = g[g.group == "held-out"].set_index("seed"); b_ = g[g.group == "seen"].set_index("seed").loc[a_.index]
        out = []
        for m in ["fpr_L2", "recall_L2", "f1_L2", "false_quarantine_rate"]:
            dd = (a_[m] - b_[m]).dropna()
            p = wilcoxon(dd).pvalue if len(dd) and (dd != 0).any() else float("nan")
            out.append(f"{m} {dd.mean():+.3f} (p={p:.3f})")
        print(f"{cfg}: held-out minus seen: " + " | ".join(out))
    print(f"saved -> {a.out}")


if __name__ == "__main__":
    main()
