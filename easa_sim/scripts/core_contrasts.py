#!/usr/bin/env python3
"""The four core component contrasts of the revised manuscript on any results CSV (revision round 1, protocol v4c check).

  python scripts/core_contrasts.py results/v4/v4c_main.csv [--disjoint results/v4/v4c_partition_disjoint.csv] [--ref results/v4/v4_main.csv ...]
      [--out results/v4/v4c_contrasts.csv] [--tex figures/v4/tab_v4c.tex]

Contrasts (a - b; paired by seed; 95% bootstrap CI of the mean; paired Wilcoxon p; seeds in which a is higher / lower):
  model      B3_net_only    - B3_local         (shared model)
  registry   EASA_net_score - B3_net_only      (revocation registry)
  composite  EASA_full      - EASA_net_score   (posture and history terms)
  grading    EASA_net_score - EASA_net_binary  (four levels vs. two; higher false quarantine = worse)
"""
import argparse
import os
import sys

import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CONTRASTS = [("model", "B3_net_only", "B3_local"), ("registry", "EASA_net_score", "B3_net_only"),
             ("composite", "EASA_full", "EASA_net_score"), ("grading", "EASA_net_score", "EASA_net_binary")]
METRICS = [("f1_L2", "F1"), ("fpr_L2", "FPR (clean)"), ("cross_site_recall_L2", "Recall (cross-site)"), ("in_dist_recall_L2", "Recall (in-dist.)"),
           ("containment_rate", "Activation"), ("replay_catch_rate", "Replay catch"), ("false_quarantine_rate", "False quarantine"),
           ("reauth_per_device_hour", "Re-auth / dev-h"), ("ttc_new_p50_s", "TTA new (s)")]


def contrast(df, a, b, m, rng, n_boot=2000):
    A = df[df.config == a].sort_values("seed").set_index("seed")[m]
    B = df[df.config == b].sort_values("seed").set_index("seed")[m]
    idx = A.index.intersection(B.index); d = (A.loc[idx] - B.loc[idx]).to_numpy(dtype=float); d = d[~np.isnan(d)]
    if len(d) < 5: return None
    p = 1.0 if np.allclose(d, 0) else stats.wilcoxon(d).pvalue
    boots = np.array([rng.choice(d, len(d)).mean() for _ in range(n_boot)]); lo, hi = np.percentile(boots, [2.5, 97.5])
    return {"delta": float(d.mean()), "lo": lo, "hi": hi, "p": p, "up": int((d > 0).sum()), "down": int((d < 0).sum()), "n": len(d),
            "mean_a": float(A.loc[idx].mean()), "mean_b": float(B.loc[idx].mean())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results"); ap.add_argument("--disjoint", default=None); ap.add_argument("--label", default="v4c")
    ap.add_argument("--out", default=None); ap.add_argument("--tex", default=None)
    a = ap.parse_args()
    rng = np.random.default_rng(0)
    df = pd.read_csv(a.results); rows = []
    sets = [("shared", df)]
    if a.disjoint: sets.append(("disjoint", pd.read_csv(a.disjoint)))
    for part, d in sets:
        for name, x, y in CONTRASTS:
            if x not in set(d.config) or y not in set(d.config): continue
            for m, lab in METRICS:
                if m not in d.columns: continue
                r = contrast(d, x, y, m, rng)
                if r: rows.append({"partition": part, "contrast": name, "a": x, "b": y, "metric": m, "label": lab, **r})
    out = pd.DataFrame(rows)
    pd.set_option("display.width", 250); pd.set_option("display.max_rows", 500)
    print(out[["partition", "contrast", "label", "mean_a", "mean_b", "delta", "lo", "hi", "p", "up", "down", "n"]].round(4).to_string(index=False))
    means = df.groupby("config")[[m for m, _ in METRICS if m in df.columns]].mean().round(3)
    print("\nper-configuration means:\n", means.to_string())
    if a.out:
        out.to_csv(a.out, index=False); print("saved ->", a.out)
    if a.tex:
        os.makedirs(os.path.dirname(a.tex) or ".", exist_ok=True)
        keep = [("model", "cross_site_recall_L2"), ("model", "f1_L2"), ("model", "containment_rate"), ("model", "in_dist_recall_L2"), ("registry", "replay_catch_rate"), ("registry", "containment_rate"), ("registry", "f1_L2"),
                ("composite", "f1_L2"), ("composite", "fpr_L2"), ("composite", "in_dist_recall_L2"), ("composite", "cross_site_recall_L2"), ("composite", "false_quarantine_rate"), ("composite", "reauth_per_device_hour"), ("composite", "ttc_new_p50_s"),
                ("grading", "false_quarantine_rate"), ("grading", "fpr_L2"), ("grading", "f1_L2"), ("grading", "cross_site_recall_L2"), ("grading", "reauth_per_device_hour")]
        names = {"model": "Shared model (B3 $-$ B3-local)", "registry": "Registry (EASA$-$PH $-$ B3)", "composite": "Composite (EASA $-$ EASA$-$PH)", "grading": "Grading (EASA$-$PH $-$ binary)"}
        lines = ["\\begin{table}[!t]", "\\caption{The four core contrasts under the identity-corrected labels (protocol v4c; 58 devices; 30 paired seeds; shared training unless stated): means of the two configurations, paired mean difference with 95\\% bootstrap CI, unadjusted paired Wilcoxon $p$ and seeds higher/lower.}",
                 "\\label{tab:v4c}", "\\centering\\scriptsize", "\\setlength{\\tabcolsep}{4pt}", "\\widebox{\\begin{tabular}{llccccc}", "\\toprule",
                 "Contrast & Metric & $a$ & $b$ & $\\Delta$ [95\\% CI] & $p$ & higher / lower \\\\", "\\midrule"]
        last = None
        for c, m in keep:
            for part in [p for p, _ in sets]:
                r = out[(out.partition == part) & (out.contrast == c) & (out.metric == m)]
                if r.empty: continue
                r = r.iloc[0]; lab = dict(METRICS)[m] + (", disjoint training" if part == "disjoint" else "")
                if part == "disjoint" and m != "cross_site_recall_L2" and c == "model": continue
                if part == "disjoint" and c != "model": continue
                first = names[c] if c != last else ""; last = c
                pv = f"$<10^{{-4}}$" if r.p < 1e-4 else f"{r.p:.3f}" if r.p >= 0.001 else f"{r.p:.1e}"
                lines.append(f"{first} & {lab} & {r.mean_a:.3f} & {r.mean_b:.3f} & ${r.delta:+.3f}$ [{r.lo:+.3f}, {r.hi:+.3f}] & {pv} & {r.up}/{r.down} \\\\")
        lines += ["\\bottomrule", "\\end{tabular}}", "\\end{table}"]
        open(a.tex, "w").write("\n".join(lines) + "\n"); print("saved ->", a.tex)


if __name__ == "__main__":
    main()
