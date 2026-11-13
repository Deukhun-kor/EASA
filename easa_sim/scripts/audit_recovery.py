#!/usr/bin/env python3
"""Recovery audit on saved traces (review round, 2026-10-08).

  python scripts/audit_recovery.py results/traces/easa_main [--config EASA_full] [--out results/audit_all_seeds.csv]

For every trace file (one per configuration and seed when the grid was run with --save-all-traces; seed 0 only
otherwise) it reports, per trace, and -- revision round 1 (editor point 4) -- aggregated over seeds per configuration
(mean, median, min, max of every column and the share of runs with at least one benign device still restricted at the
end):
  * benign (never-attacked) devices: number of L2+ episodes, median / max dwell, and how many were still restricted
    at the end of the run (possible L2 lock-in, Section 3.4 of the paper);
  * compromised devices: post-attack time spent at L2 vs. L3 (L3 is absorbing within a run);
  * pending step-ups that were executed vs. cancelled.
Only the per-epoch log columns written by runner.run_once(save_traces=True) are used.
"""
import argparse
import glob
import os
import sys

import numpy as np
import pandas as pd


def episodes(mask: np.ndarray):
    """(start, end) index pairs of maximal True runs."""
    out, i = [], 0
    while i < len(mask):
        if mask[i]:
            j = i
            while j < len(mask) and mask[j]: j += 1
            out.append((i, j)); i = j
        else:
            i += 1
    return out


def audit(df: pd.DataFrame, epoch_s: float) -> dict:
    res = {}
    ever = df.groupby("device")["attacking"].transform("max").astype(bool)
    benign = df[~ever]; comp = df[ever]
    n_ep, dwell, stuck_l2, stuck_l3, l2_recovered = 0, [], 0, 0, []
    for dev, g in benign.groupby("device"):
        lv = g["level"].to_numpy()
        for a, b in episodes(lv >= 2):
            n_ep += 1; dwell.append((b - a) * epoch_s)
            if b == len(lv):
                if lv[-1] >= 3: stuck_l3 += 1      # false quarantine (L3 absorbing)
                else: stuck_l2 += 1                # L2 lock-in: never relaxed within the run
            elif lv[a:b].max() == 2:
                l2_recovered.append((b - a) * epoch_s)   # L2-only episode that did recover
    res["benign_devices"] = int(benign["device"].nunique())
    res["benign_L2plus_episodes"] = n_ep
    res["benign_dwell_median_s"] = float(np.median(dwell)) if dwell else 0.0
    res["benign_dwell_max_s"] = float(np.max(dwell)) if dwell else 0.0
    res["benign_L2_recovered_episodes"] = len(l2_recovered)
    res["benign_L2_recovery_median_s"] = float(np.median(l2_recovered)) if l2_recovered else float("nan")
    res["benign_stuck_L2_at_end"] = stuck_l2
    res["benign_stuck_L3_at_end"] = stuck_l3
    l2, l3 = 0, 0
    for dev, g in comp.groupby("device"):
        a = g["attacking"].to_numpy(); lv = g["level"].to_numpy()
        last_attack = np.flatnonzero(a).max()
        post = lv[last_attack + 1:]
        l2 += int((post == 2).sum()); l3 += int((post == 3).sum())
    n_comp = max(1, comp["device"].nunique())
    res["compromised_devices"] = int(comp["device"].nunique())
    res["post_attack_L2_s_per_device"] = l2 * epoch_s / n_comp
    res["post_attack_L3_s_per_device"] = l3 * epoch_s / n_comp
    res["deferred_stepups"] = int(df["deferred_stepup"].sum())
    res["reauths"] = int(df["reauth"].sum())
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("traces_dir"); ap.add_argument("--config", default=None); ap.add_argument("--epoch", type=float, default=10.0)
    ap.add_argument("--out", default=None, help="write per-trace rows (and <out>_agg.csv aggregated over seeds)")
    a = ap.parse_args()
    rows = []
    files = sorted(glob.glob(os.path.join(a.traces_dir, "*.parquet")) + glob.glob(os.path.join(a.traces_dir, "*.csv.gz")))
    if not files:
        sys.exit(f"no trace files (*.parquet / *.csv.gz) in {a.traces_dir}")
    for f in files:
        name = os.path.basename(f).replace(".csv.gz", "").replace(".parquet", "")
        if a.config and not name.startswith(a.config): continue
        df = pd.read_parquet(f) if f.endswith(".parquet") else pd.read_csv(f)
        r = audit(df, a.epoch); r["trace"] = name; rows.append(r)
    ap2 = None
    out = pd.DataFrame(rows)
    out["config"] = out["trace"].str.replace(r"_seed\d+$", "", regex=True)
    out["seed"] = out["trace"].str.extract(r"_seed(\d+)$")[0].astype(int)
    out = out.set_index("trace")
    pd.set_option("display.width", 250)
    print(out.round(1).to_string())
    num = [c for c in out.columns if c not in ("config", "seed")]
    agg = out.groupby("config")[num].agg(["mean", "median", "min", "max"])
    agg[("runs", "n")] = out.groupby("config")["seed"].count()
    agg[("runs_with_benign_stuck_L2", "share")] = out.groupby("config")["benign_stuck_L2_at_end"].apply(lambda s_: float((s_ > 0).mean()))
    agg[("runs_with_benign_stuck_L3", "share")] = out.groupby("config")["benign_stuck_L3_at_end"].apply(lambda s_: float((s_ > 0).mean()))
    print("\n=== aggregated over seeds ===")
    print(agg.round(2).T.to_string())
    if a.out:
        out.to_csv(a.out); agg.to_csv(a.out.replace(".csv", "_agg.csv"))
        print(f"saved -> {a.out}, {a.out.replace('.csv', '_agg.csv')}")


if __name__ == "__main__":
    main()
