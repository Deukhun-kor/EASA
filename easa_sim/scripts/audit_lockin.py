#!/usr/bin/env python3
"""Lock-in attribution over all seeds (revision round 1, editor point 4 / R4).

  python scripts/audit_lockin.py results/traces/r1_recovery --a EASA_full --b EASA_net_score --results results/r1_recovery.csv --out results/r1_lockin.csv

For every seed, pairs the traces of configuration A (default EASA_full) and B (default EASA_net_score = EASA-PH), which
replay identical device traces and campaigns, and for every benign (never-attacked) device reports how long it was
restricted (level >= 2) under each, and -- for devices restricted >= `--min-dwell` s under A -- the network score during
the restriction (mean, 10th/90th percentile, share of epochs at or above tau_L1 and tau_L2 of A), the posture and
history terms, and whether B restricted the same device. The aggregate answers: are the devices that A holds at L2
devices whose *network* evidence alone would place them below A's thresholds (a calibration/decay interaction) or
devices that only the posture/history terms push down?

Writes <out> (one row per benign device restricted under A) and <out>_agg.csv.
"""
import argparse
import glob
import os

import numpy as np
import pandas as pd


def restricted_spans(lv: np.ndarray):
    out, i = [], 0
    while i < len(lv):
        if lv[i] >= 2:
            j = i
            while j < len(lv) and lv[j] >= 2: j += 1
            out.append((i, j)); i = j
        else:
            i += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("traces_dir"); ap.add_argument("--a", default="EASA_full"); ap.add_argument("--b", default="EASA_net_score")
    ap.add_argument("--results", required=True, help="result CSV of the grid (for tau_L1 / tau_L2 per config and seed)")
    ap.add_argument("--out", default="results/r1_lockin.csv"); ap.add_argument("--epoch", type=float, default=10.0)
    ap.add_argument("--min-dwell", type=float, default=300.0)
    args = ap.parse_args()
    res = pd.read_csv(args.results).set_index(["config", "seed"])
    rows, per_seed = [], []
    load = lambda f: pd.read_parquet(f) if f.endswith(".parquet") else pd.read_csv(f)
    files = sorted(glob.glob(os.path.join(args.traces_dir, f"{args.a}_seed*.parquet")) + glob.glob(os.path.join(args.traces_dir, f"{args.a}_seed*.csv.gz")))
    for fa in files:
        seed = int(os.path.basename(fa).split("_seed")[1].split(".")[0])
        fb = fa.replace(f"{args.a}_seed", f"{args.b}_seed")
        if not os.path.exists(fb): continue
        A, B = load(fa), load(fb)
        tauA = res.loc[(args.a, seed)]; tauB = res.loc[(args.b, seed)]
        everA = A.groupby("device")["attacking"].transform("max").astype(bool)
        benA = A[~everA]; benB = B[B["device"].isin(benA["device"].unique())]
        n_ben = benA["device"].nunique()
        restA = benA.groupby("device")["level"].apply(lambda s: int((s >= 2).sum()))
        restB = benB.groupby("device")["level"].apply(lambda s: int((s >= 2).sum()))
        both = pd.concat([restA.rename("A"), restB.rename("B")], axis=1).fillna(0)
        per_seed.append({"seed": seed, "benign_devices": n_ben,
                         "devices_restricted_A": int((both.A > 0).sum()), "devices_restricted_B": int((both.B > 0).sum()),
                         "devices_restricted_A_not_B": int(((both.A > 0) & (both.B == 0)).sum()),
                         "devices_restricted_B_not_A": int(((both.B > 0) & (both.A == 0)).sum()),
                         "restricted_epochs_A": int(both.A.sum()), "restricted_epochs_B": int(both.B.sum()),
                         "excess_epochs_A_minus_B": int(both.A.sum() - both.B.sum())})
        for dev, g in benA.groupby("device"):
            lv = g["level"].to_numpy()
            spans = restricted_spans(lv)
            dwell = sum(j - i for i, j in spans) * args.epoch
            if dwell < args.min_dwell: continue
            r = g[g["level"] >= 2]
            gb = benB[benB["device"] == dev]
            rows.append({
                "seed": seed, "device": dev, "dclass": g["dclass"].iloc[0], "dwell_A_s": dwell, "stuck_at_end_A": int(lv[-1] >= 2), "max_level_A": int(lv.max()),
                "S_net_mean": r["S_net"].mean(), "S_net_p10": r["S_net"].quantile(0.1), "S_net_p90": r["S_net"].quantile(0.9),
                "share_S_net_ge_tauL1_A": float((r["S_net"] >= tauA["tau_L1"]).mean()), "share_S_net_ge_tauL2_A": float((r["S_net"] >= tauA["tau_L2"]).mean()),
                "share_S_net_ge_tauL2_B": float((r["S_net"] >= tauB["tau_L2"]).mean()),
                "S_pos_mean": r["S_pos"].mean(), "S_hist_end": r["S_hist"].iloc[-1], "S_hist_mean": r["S_hist"].mean(), "T_mean": r["T"].mean(),
                "T_if_hist_1": (r["T"] + 0.15 * (1.0 - r["S_hist"])).mean(),      # the composite with the history term at its calibration value
                "tauL1_A": tauA["tau_L1"], "tauL2_A": tauA["tau_L2"], "tauL2_B": tauB["tau_L2"],
                "dwell_B_s": float((gb["level"] >= 2).sum() * args.epoch), "max_level_B": int(gb["level"].max()) if len(gb) else -1,
            })
    dev = pd.DataFrame(rows); ps = pd.DataFrame(per_seed)
    dev.to_csv(args.out, index=False)
    agg = {
        "seeds": len(ps), "benign_devices_per_run": ps["benign_devices"].mean(),
        "devices_restricted_A_per_run": ps["devices_restricted_A"].mean(), "devices_restricted_B_per_run": ps["devices_restricted_B"].mean(),
        "devices_restricted_A_not_B_per_run": ps["devices_restricted_A_not_B"].mean(), "devices_restricted_B_not_A_per_run": ps["devices_restricted_B_not_A"].mean(),
        "restricted_epochs_A_per_run": ps["restricted_epochs_A"].mean(), "restricted_epochs_B_per_run": ps["restricted_epochs_B"].mean(),
        f"long_restrictions_A_per_run(>= {args.min_dwell:.0f}s)": len(dev) / max(1, len(ps)),
        "of_which_stuck_at_end": dev["stuck_at_end_A"].mean() if len(dev) else float("nan"),
        "of_which_also_restricted_under_B": float((dev["dwell_B_s"] > 0).mean()) if len(dev) else float("nan"),
        "of_which_B_dwell_median_s": dev["dwell_B_s"].median() if len(dev) else float("nan"),
        "S_net_mean_median": dev["S_net_mean"].median() if len(dev) else float("nan"),
        "share_S_net_ge_tauL1_A_median": dev["share_S_net_ge_tauL1_A"].median() if len(dev) else float("nan"),
        "share_S_net_ge_tauL2_B_median": dev["share_S_net_ge_tauL2_B"].median() if len(dev) else float("nan"),
        "share_devices_S_net_mean_above_tauL2_B": float((dev["S_net_mean"] >= dev["tauL2_B"]).mean()) if len(dev) else float("nan"),
        "share_devices_T_if_hist_1_above_tauL2_A": float((dev["T_if_hist_1"] >= dev["tauL2_A"]).mean()) if len(dev) else float("nan"),
        "S_hist_end_median": dev["S_hist_end"].median() if len(dev) else float("nan"),
        "S_pos_mean_median": dev["S_pos_mean"].median() if len(dev) else float("nan"),
        "dclass_counts": dev["dclass"].value_counts().to_dict() if len(dev) else {},
    }
    pd.Series(agg).to_csv(args.out.replace(".csv", "_agg.csv"))
    ps.to_csv(args.out.replace(".csv", "_per_seed.csv"), index=False)
    pd.set_option("display.width", 200)
    print(pd.Series(agg).to_string())
    print(f"\nsaved -> {args.out}, {args.out.replace('.csv', '_agg.csv')}, {args.out.replace('.csv', '_per_seed.csv')}")


if __name__ == "__main__":
    main()
