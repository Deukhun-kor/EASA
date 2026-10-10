#!/usr/bin/env python3
"""Produce paper tables (LaTeX) and figures (PDF) from the results CSVs (protocol v2 metrics).

  python scripts/make_figures.py results/easa_main.csv --traces results/traces --out figures
  python scripts/make_figures.py results/easa_main.csv --outage results/outage.csv --sens results/sensitivity.csv --out figures

Writes into --out:
  tab_results.tex      main table (mean +- std [95% CI]) for the headline metrics
  tab_family.tex       per-family recall table
  tab_thresholds.tex   calibrated thresholds per configuration
  tab_rtt.tex          real-cloud call statistics
  tab_replay.tex       credential-replay denominators (runs / campaigns with a revoked donor, catch all vs conditional)
  tab_benign.tex       benign-side cost (clean-device FPR, restricted share of all benign epochs, dwell, false quarantine)
  tab_paired.tex       paired differences vs EASA_full with bootstrap CI, Holm p and seed-wise wins
  significance.txt     paired Wilcoxon signed-rank vs EASA_full, Holm-corrected
  summary.md           everything above as markdown (for the chat / notes)
  fig_metrics.pdf      box plots, 6 headline metrics x 6 configurations
  fig_family.pdf       per-family recall, grouped bars
  fig_cross_site.pdf   in-distribution vs cross-site recall per configuration
  fig_trust_trace.pdf  trust trajectory of a compromised vs a benign device (seed-0 trace)
  fig_rtt.pdf          cloud RTT per configuration
  fig_outage.pdf       (with --outage) EASA_full with vs without the cloud outage
  fig_sensitivity.pdf  (with --sens) F1 / cross-site / FPR across the sensitivity axes
"""
import argparse
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scipy import stats  # noqa: E402

from easa.metrics import bootstrap_ci  # noqa: E402

ORDER = ["B0_static", "B1_vnsf", "B2_rules", "B3_net_only", "EASA_minus_C",
         "EASA_net_score", "EASA_no_energy", "EASA_model_only", "EASA_rev_only",   # follow-up ablations (extra_configs)
         "EASA_full", "EASA_reset"]
LABEL = {"B0_static": "B0 static", "B1_vnsf": "B1 VNSF", "B2_rules": "B2 rules", "B3_net_only": "B3 net-only",
         "EASA_minus_C": "EASA$-$C", "EASA_full": "EASA",
         "EASA_net_score": "EASA$-$PH", "EASA_no_energy": "EASA, no energy-aware action",
         "EASA_model_only": "EASA, model only", "EASA_rev_only": "EASA, registry only",
         "EASA_reset": "EASA, history reset"}
# categorical palette validated for CVD separation (dataviz validator, light surface); EASA is also hatched
PALETTE = {"B0_static": "#2a78d6", "B1_vnsf": "#1baf7a", "B2_rules": "#4a3aa7", "B3_net_only": "#eda100",
           "EASA_minus_C": "#e34948", "EASA_full": "#008300",
           "EASA_net_score": "#7f7f7f", "EASA_no_energy": "#9e9e9e", "EASA_model_only": "#bdbdbd", "EASA_rev_only": "#d9d9d9",
           "EASA_reset": "#5a9e5a"}
HATCH = {"EASA_full": "//"}

# (column, label, higher-is-better, format)
MAIN = [("f1_L2", "F1 ($L_2$)", True, "{:.3f}"),
        ("fpr_L2", "FPR", False, "{:.3f}"),
        ("in_dist_recall_L2", "Recall (in-dist.)", True, "{:.3f}"),
        ("cross_site_recall_L2", "Recall (cross-site)", True, "{:.3f}"),
        ("containment_rate", "Containment", True, "{:.3f}"),
        ("ttc_p50_s", "TTC p50 (s)", False, "{:.0f}"),
        ("false_quarantine_rate", "False quarantine", False, "{:.3f}"),
        ("reauth_per_device_hour", "Re-auth / dev-h", False, "{:.3f}"),
        ("replay_catch_rate", "Replay catch (all runs)", True, "{:.3f}")]
BOX = [("f1_L2", "F1 ($L_2$)"), ("fpr_L2", "FPR (clean devices)"), ("in_dist_recall_L2", "Recall, in-distribution"),
       ("cross_site_recall_L2", "Recall, cross-site"), ("containment_rate", "Containment rate"),
       ("replay_catch_rate", "Credential-replay catch (all runs)")]

plt.rcParams.update({"font.size": 8, "axes.titlesize": 9, "axes.labelsize": 8, "legend.fontsize": 7,
                     "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
                     "grid.alpha": 0.25, "grid.linewidth": 0.5, "pdf.fonttype": 42})


def _cfgs(df):
    return [c for c in ORDER if c in df["config"].unique()]


def _tex(s):
    return s.replace("_", r"\_")


# ----------------------------------------------------------------------------- tables
def results_table(df, out_tex):
    rng = np.random.default_rng(0)
    rows, md = [], []
    for cfg in _cfgs(df):
        g = df[df["config"] == cfg]
        cells, mcells = [LABEL[cfg]], [LABEL[cfg].replace("$-$", "-")]
        for m, _, _, fmt in MAIN:
            v = g[m].to_numpy(dtype=float)
            if np.all(np.isnan(v)):
                cells.append("--"); mcells.append("--"); continue
            lo, hi = bootstrap_ci(v, rng)
            sd = np.nanstd(v, ddof=1)   # sample std, as in every other table
            cells.append(f"{fmt.format(np.nanmean(v))} $\\pm$ {fmt.format(sd)}")
            mcells.append(f"{fmt.format(np.nanmean(v))} ± {fmt.format(sd)} [{fmt.format(lo)}, {fmt.format(hi)}]")
        rows.append(" & ".join(cells) + r" \\"); md.append("| " + " | ".join(mcells) + " |")
    head = " & ".join(["Configuration"] + [lab for _, lab, _, _ in MAIN]) + r" \\"
    tex = ("\\begin{table}[!t]\n\\caption{Main results over 30 seeds (mean $\\pm$ sample std; 95\\% bootstrap CIs in the released "
           "\\texttt{summary.md}). All configurations except B0 are calibrated to a 2\\% target false-positive rate on the "
           "calibration segment; FPR is measured on never-compromised devices in the evaluation segment. Configurations with a cloud "
           "path (B2, B3, EASA$-$PH, EASA) ran against the deployed Cloud Run service; B0, B1 and EASA$-$C issue no cloud calls. Replay catch is the unconditional share of credential-replay "
           "device-epochs at $L_3$ over all 30 runs (Table~\\ref{tab:replay} gives the denominators).}\n"
           "\\label{tab:results}\n\\centering\\scriptsize\n\\setlength{\\tabcolsep}{3pt}\n\\widebox{%\n"
           "\\begin{tabular}{l" + "c" * len(MAIN) + "}\n\\toprule\n" + head + "\n\\midrule\n" + "\n".join(rows)
           + "\n\\bottomrule\n\\end{tabular}}\n\\end{table}\n")
    open(out_tex, "w").write(tex)
    return ["| Configuration | " + " | ".join(lab for _, lab, _, _ in MAIN) + " |",
            "|" + "---|" * (len(MAIN) + 1)] + md


def family_table(df, out_tex):
    rows = []
    for _, r in df.iterrows():
        for m in re.finditer(r"(\w+)=([\d.]+)", str(r.get("recall_by_family", ""))):
            rows.append((r["config"], m.group(1), float(m.group(2))))
    fam = pd.DataFrame(rows, columns=["config", "family", "recall"])
    if fam.empty: return [], None
    piv = fam.pivot_table(index="family", columns="config", values="recall", aggfunc="mean")
    cnt = fam.pivot_table(index="family", columns="config", values="recall", aggfunc="count")
    cfgs = [c for c in ORDER if c in piv.columns]
    piv = piv[cfgs]; cnt = cnt[cfgs]
    order = ["DoS", "DDoS", "Mirai", "Recon", "Spoofing", "Web", "FirmwareTamper", "CredentialReplay"]
    piv = piv.reindex([f for f in order if f in piv.index])
    lines = []
    for fam_, r in piv.iterrows():
        lines.append(f"{fam_} ({int(cnt.loc[fam_].max())}) & " + " & ".join(f"{v:.2f}" for v in r.values) + r" \\")
    tex = ("\\begin{table}[!t]\n\\caption{Recall at the $L_2$ boundary per attack family (mean over the runs in which the "
           "family occurs; number of runs in parentheses).}\n\\label{tab:family}\n\\centering\\footnotesize\n\\setlength{\\tabcolsep}{4pt}\n"
           "\\widebox{\\begin{tabular}{l" + "c" * len(cfgs) + "}\n\\toprule\nFamily & " + " & ".join(LABEL[c] for c in cfgs)
           + r" \\" + "\n\\midrule\n" + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}}\n\\end{table}\n")
    open(out_tex, "w").write(tex)
    md = ["| Family | " + " | ".join(LABEL[c].replace("$-$", "-") for c in cfgs) + " |", "|" + "---|" * (len(cfgs) + 1)]
    md += [f"| {f} | " + " | ".join(f"{v:.2f}" for v in r.values) + " |" for f, r in piv.iterrows()]
    return md, piv


def threshold_table(df, out_tex):
    if "tau_L2" not in df.columns: return []
    df = df.copy(); df["tau_L3"] = df["tau_L3"].clip(lower=0.0)   # a negative tau_L3 is unreachable (T in [0,1]) == 0
    g = df.groupby("config")[["tau_L1", "tau_L2", "tau_L3"]].agg(["mean", "std"])
    cfgs = _cfgs(df); lines, md = [], ["| Configuration | τ_L1 | τ_L2 | τ_L3 |", "|---|---|---|---|"]
    for c in cfgs:
        cells = [f"{g.loc[c, (k, 'mean')]:.3f} $\\pm$ {g.loc[c, (k, 'std')]:.3f}" for k in ["tau_L1", "tau_L2", "tau_L3"]]
        lines.append(LABEL[c] + " & " + " & ".join(cells) + r" \\")
        md.append(f"| {LABEL[c]} | " + " | ".join(cl.replace("$\\pm$", "±") for cl in cells) + " |")
    tex = ("\\begin{table}[H]\n\\caption{Calibrated entry thresholds (mean $\\pm$ std over seeds). B0 has no trust "
           "computation and keeps the nominal values; $\\tau_{L3}$ is floored at 0 by the calibration rule.}\n\\label{tab:thresholds}\n\\centering\\footnotesize\n"
           "\\begin{tabular}{lccc}\n\\toprule\nConfiguration & $\\tau_{L1}$ & $\\tau_{L2}$ & $\\tau_{L3}$ \\\\\n\\midrule\n"
           + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}\n\\end{table}\n")
    open(out_tex, "w").write(tex)
    return md


def rtt_table(df, out_tex):
    if "rtt_ms_p50" not in df.columns or df["rtt_ms_p50"].isna().all(): return []
    d = df.dropna(subset=["rtt_ms_p50"])
    cols = ["n_calls", "rtt_ms_p50", "rtt_ms_p95", "rtt_ms_max"] + [c for c in ["n_cloud_retries", "n_cloud_errors"] if c in d.columns]
    g = d.groupby("config")[cols].mean()
    cfgs = [c for c in ORDER if c in g.index]
    lines = [LABEL[c] + " & " + " & ".join(f"{g.loc[c, k]:.0f}" if k.startswith("n_") else f"{g.loc[c, k]:.0f}" for k in cols) + r" \\" for c in cfgs]
    head = {"n_calls": "Calls / run", "rtt_ms_p50": "RTT p50 (ms)", "rtt_ms_p95": "RTT p95 (ms)", "rtt_ms_max": "RTT max (ms)",
            "n_cloud_retries": "Retried", "n_cloud_errors": "Dropped"}
    pooled = {c: float(d[d["config"] == c]["rtt_ms_max"].max()) for c in cfgs}
    pooled_s = ", ".join(f"{LABEL[c]} {pooled[c]:.0f}" for c in cfgs)
    tex = ("\\begin{table}[H]\n\\caption{Real cloud calls per simulated hour (Cloud Run, Seoul region). Calls include the "
           "federated warm-up; RTT columns are means over runs of the per-run median, 95th percentile and maximum; the pooled "
           "maximum over the runs of the main experiment was " + pooled_s + "\\,ms (Section~\\ref{subsec:res-latency} counts the stalled calls). ``Retried'' and ``Dropped'' count calls that needed a retry or were "
           "given up after three retries.}\n"
           "\\label{tab:rtt}\n\\centering\\footnotesize\n\\begin{tabular}{l" + "c" * len(cols) + "}\n\\toprule\nConfiguration & "
           + " & ".join(head[k] for k in cols) + r" \\" + "\n\\midrule\n" + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}\n\\end{table}\n")
    open(out_tex, "w").write(tex)
    return ["| Configuration | " + " | ".join(head[k] for k in cols) + " |", "|" + "---|" * (len(cols) + 1)] + \
           [f"| {LABEL[c]} | " + " | ".join(f"{g.loc[c, k]:.0f}" for k in cols) + " |" for c in cfgs]


def significance(df, out_txt, ref="EASA_full"):
    """Paired Wilcoxon signed-rank vs. the reference configuration over seeds, Holm-corrected per metric."""
    lines = []
    for m, lab, hib, _ in MAIN:
        r = df[df["config"] == ref].sort_values("seed")[m].to_numpy(dtype=float)
        pvals, names, deltas = [], [], []
        for cfg in _cfgs(df):
            if cfg == ref: continue
            o = df[df["config"] == cfg].sort_values("seed")[m].to_numpy(dtype=float)
            n = min(len(r), len(o)); rr, oo = r[:n], o[:n]
            mask = ~(np.isnan(rr) | np.isnan(oo))
            if mask.sum() < 5 or np.allclose(rr[mask], oo[mask]):
                continue
            p = stats.wilcoxon(rr[mask], oo[mask]).pvalue
            pvals.append(p); names.append(cfg); deltas.append(float(np.mean(rr[mask] - oo[mask])))
        order = np.argsort(pvals); k = len(pvals); adj, running = {}, 0.0
        for rank, i in enumerate(order):          # Holm step-down
            running = max(running, pvals[i] * (k - rank)); adj[names[i]] = min(1.0, running)
        parts = []
        for n_, d in zip(names, deltas):
            better = (d > 0) == hib
            star = "***" if adj[n_] < 0.001 else "**" if adj[n_] < 0.01 else "*" if adj[n_] < 0.05 else "n.s."
            parts.append(f"{n_}: Δ(EASA−{n_})={d:+.3f} (EASA {'better' if better else 'worse'}) p_holm={adj[n_]:.4f} {star}")
        lines.append(f"{lab}: " + "; ".join(parts))
    open(out_txt, "w").write("\n".join(lines) + "\n")
    return lines


def replay_table(df, out_tex):
    """Credential-replay denominators: runs with >=1 revoked donor, campaigns with a revoked donor, catch (all / conditional)."""
    cfgs = [c for c in _cfgs(df) if c != "B0_static"]
    lines, md = [], ["| Configuration | runs with a revocation | campaigns with revoked donor | catch (all runs) | catch (runs with revocation) |", "|---|---|---|---|---|"]
    for c in cfgs:
        g = df[df["config"] == c]
        n_runs = int((g["replay_donor_revoked_rate"] > 0).sum()); n_tot = len(g)
        camp = float(g["replay_donor_revoked_rate"].mean())
        allr = float(g["replay_catch_rate"].mean()); allsd = float(g["replay_catch_rate"].std())
        cond = g["replay_catch_rate_cond"].dropna()
        cs = f"{cond.mean():.3f} $\\pm$ {cond.std():.3f} ($n={len(cond)}$)" if len(cond) >= 2 else "--"
        lines.append(f"{LABEL[c]} & {n_runs}/{n_tot} & {100*camp:.0f}\\% & {allr:.3f} $\\pm$ {allsd:.3f} & {cs} \\\\")
        md.append(f"| {LABEL[c]} | {n_runs}/{n_tot} | {100*camp:.0f}% | {allr:.3f} ± {allsd:.3f} | {cs.replace('$\\\\pm$', '±')} |")
    tex = ("\\begin{table}[!t]\n\\caption{Credential-replay path: denominators. ``Runs with a revocation'': runs in which at least one "
           "replay campaign's donor credential had been revoked (at $L_3$) anywhere by the end of the run; ``campaigns with revoked "
           "donor'': share of replay campaigns (1.4 per run on average) whose donor was revoked; catch rates are the share of "
           "replay device-epochs at $L_3$, over all runs and over the runs with a revocation only (mean $\\pm$ std, $n$ runs). "
           "The conditional subsets differ between configurations because revocation depends on the detector.}\n"
           "\\label{tab:replay}\n\\centering\\footnotesize\n\\setlength{\\tabcolsep}{4pt}\n\\widebox{\\begin{tabular}{lcccc}\n\\toprule\nConfiguration & Runs with revocation & "
           "Campaigns, donor revoked & Catch (all runs) & Catch (runs with revocation) \\\\\n\\midrule\n"
           + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}}\n\\end{table}\n")
    open(out_tex, "w").write(tex)
    return md


def benign_table(df, out_tex):
    """Benign-side service loss: FPR on clean devices, restriction fraction over all benign epochs, post-attack dwell, false quarantine."""
    cols = [("fpr_L2", "FPR (clean devices)", "{:.3f}"), ("fpr_L2_all_epochs", "Restricted share (all benign epochs)", "{:.3f}"),
            ("post_attack_dwell_s", "Post-attack dwell (s / compromised device)", "{:.0f}"), ("false_quarantine_rate", "False quarantine", "{:.3f}")]
    cfgs = _cfgs(df); lines = []
    md = ["| Configuration | " + " | ".join(l for _, l, _ in cols) + " |", "|" + "---|" * (len(cols) + 1)]
    for c in cfgs:
        g = df[df["config"] == c]
        cells = [f"{fmt.format(g[m].mean())} $\\pm$ {fmt.format(g[m].std())}" for m, _, fmt in cols]
        lines.append(LABEL[c] + " & " + " & ".join(cells) + r" \\")
        md.append(f"| {LABEL[c]} | " + " | ".join(x.replace("$\\pm$", "±") for x in cells) + " |")
    tex = ("\\begin{table}[!t]\n\\caption{Benign-side cost over 30 seeds (mean $\\pm$ std). FPR counts only epochs of devices that are "
           "never compromised in the run; the restricted share counts every benign device-epoch (level $\\ge L_2$ while the device is "
           "not under a campaign), including the pre-attack and post-attack epochs of devices that are compromised at some point; "
           "post-attack dwell is the restricted time per compromised device after its campaigns end ($L_3$ is absorbing within a run).}\n"
           "\\label{tab:benign}\n\\centering\\footnotesize\n\\setlength{\\tabcolsep}{4pt}\n\\widebox{\\begin{tabular}{lcccc}\n\\toprule\nConfiguration & "
           + " & ".join(l for _, l, _ in cols) + " \\\\\n\\midrule\n" + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}}\n\\end{table}\n")
    open(out_tex, "w").write(tex)
    return md


PAIRED_DET = [m for m in MAIN if m[0] in ("f1_L2", "fpr_L2", "in_dist_recall_L2", "cross_site_recall_L2", "containment_rate", "replay_catch_rate")]
PAIRED_COST = [m for m in MAIN if m[0] in ("false_quarantine_rate", "reauth_per_device_hour")] + \
              [("fpr_L2_all_epochs", "Restricted share (all benign epochs)", False, "{:.3f}"),
               ("post_attack_dwell_s", "Post-attack dwell (s)", False, "{:.0f}")]


def episode_table(df, out_tex):
    """Restriction-activation decomposition: already restricted at onset vs newly restricted; TTC of the latter."""
    if "containment_new_rate" not in df.columns: return []
    cols = [("containment_rate", "Activated (any)", "{:.3f}"), ("containment_pre_restricted_rate", "Already restricted at onset", "{:.3f}"),
            ("containment_new_rate", "Newly restricted", "{:.3f}"), ("ttc_new_p50_s", "TTC p50, newly restricted (s)", "{:.0f}")]
    lines, md = [], ["| Configuration | " + " | ".join(l for _, l, _ in cols) + " |", "|" + "---|" * (len(cols) + 1)]
    for c in _cfgs(df):
        g = df[df["config"] == c]
        cells = [f"{fmt.format(g[m].mean())} $\\pm$ {fmt.format(g[m].std())}" if not g[m].isna().all() else "--" for m, _, fmt in cols]
        lines.append(LABEL[c] + " & " + " & ".join(cells) + r" \\"); md.append(f"| {LABEL[c]} | " + " | ".join(x.replace("$\\pm$", "±") for x in cells) + " |")
    tex = ("\\begin{table}[!t]\n\\caption{Restriction activation decomposed per attack episode (mean $\\pm$ std over seeds): "
           "share of episodes during which the device was at $\\ge L_2$ at any time, split into episodes that began while the "
           "device was already restricted (carried over from an earlier episode; $L_3$ is absorbing) and episodes in which the "
           "restriction was newly activated; TTC is reported for the latter only.}\n\\label{tab:episodes}\n\\centering\\footnotesize\n"
           "\\setlength{\\tabcolsep}{4pt}\n\\widebox{\\begin{tabular}{lcccc}\n\\toprule\nConfiguration & " + " & ".join(l for _, l, _ in cols)
           + " \\\\\n\\midrule\n" + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}}\n\\end{table}\n")
    open(out_tex, "w").write(tex)
    return md


def paired_table(df, out_tex, ref="EASA_full", n_boot=2000):
    """Two tables: detection metrics (tab:paired) and benign-side cost metrics (tab:paired-cost)."""
    md = _paired_table(df, out_tex, PAIRED_DET, "tab:paired",
                       "Paired differences, detection metrics: mean of EASA $-$ other over the 30 seeds, 95\\% bootstrap CI, "
                       "Holm-corrected paired Wilcoxon $p$ (six comparisons per metric), and seeds in which EASA is better (higher for all "
                       "metrics except FPR, where lower is better). Replay catch is unconditional.",
                       ref, n_boot)
    md += _paired_table(df, out_tex.replace("tab_paired", "tab_paired_cost"), PAIRED_COST, "tab:paired-cost",
                        "Paired differences, benign-side cost metrics (same conventions as Table~\\ref{tab:paired}; "
                        "EASA is better when lower).", ref, n_boot, placement="!b")
    return md


def _paired_table(df, out_tex, mets, label, caption, ref="EASA_full", n_boot=2000, placement="!t"):
    rng = np.random.default_rng(0)
    r_all = df[df["config"] == ref].sort_values("seed")
    lines, md = [], ["| Metric | Comparison | Δ (EASA − other) | 95% CI | p (Holm) | seeds EASA better |", "|---|---|---|---|---|---|"]
    for m, lab, hib, fmt in mets:
        r = r_all[m].to_numpy(dtype=float)
        rows = []
        for cfg in _cfgs(df):
            if cfg == ref: continue
            o = df[df["config"] == cfg].sort_values("seed")[m].to_numpy(dtype=float)
            n = min(len(r), len(o)); d = r[:n] - o[:n]; d = d[~np.isnan(d)]
            if len(d) < 5: continue
            if np.allclose(d, 0): p = 1.0
            else: p = stats.wilcoxon(d).pvalue
            boots = np.array([rng.choice(d, len(d)).mean() for _ in range(n_boot)])
            lo, hi = np.percentile(boots, [2.5, 97.5])
            better = int(((d > 0) if hib else (d < 0)).sum()); ties = int((d == 0).sum())
            rows.append([cfg, float(d.mean()), lo, hi, p, better, ties, len(d)])
        pv = np.array([x[4] for x in rows]); order = np.argsort(pv); k = len(pv); running = 0.0; adj = [0.0] * k
        for rank, i in enumerate(order):
            running = max(running, pv[i] * (k - rank)); adj[i] = min(1.0, running)
        first = True
        for (cfg, dm, lo, hi, p, better, ties, n), pa in zip(rows, adj):
            pstr = "$<0.001$" if pa < 0.001 else f"{pa:.3f}"
            lines.append((lab if first else "") + f" & {LABEL[cfg]} & {fmt.format(dm).replace('-', '$-$') if dm < 0 else '+' + fmt.format(dm)} & $[{fmt.format(lo)}, {fmt.format(hi)}]$ & {pstr} & {better}/{n} \\\\")
            md.append(f"| {lab if first else ''} | {LABEL[cfg]} | {dm:+.3f} | [{lo:.3f}, {hi:.3f}] | {pstr} | {better}/{n} |")
            first = False
        lines.append(r"\midrule")
    lines = lines[:-1]
    tex = ("\\begin{table}[" + placement + "]\n\\caption{" + caption + "}\n"
           "\\label{" + label + "}\n\\centering\\scriptsize\n\\setlength{\\tabcolsep}{4pt}\n\\begin{tabular}{llcccc}\n\\toprule\n"
           "Metric & vs. & $\\Delta$ (EASA $-$ other) & 95\\% CI & $p$ (Holm) & Seeds EASA better \\\\\n\\midrule\n"
           + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}\n\\end{table}\n")
    open(out_tex, "w").write(tex)
    return md


def lowbattery_table(df_lb, out_tex):
    """Low-battery scenario: selector isolated by EASA_no_energy (same seeds, same battery draws)."""
    cols = [("deferred_cancelled", "Deferred, cancelled", "{:.2f}"), ("pending_at_end", "Deferred, pending at end", "{:.2f}"),
            ("reauth_per_device_hour", "Re-auth / dev-h", "{:.3f}"), ("energy_final_mean", "Residual energy", "{:.3f}"),
            ("f1_L2", "F1", "{:.3f}"), ("fpr_L2", "FPR (clean)", "{:.3f}"), ("containment_rate", "Containment", "{:.3f}"),
            ("post_attack_dwell_s", "Dwell (s)", "{:.0f}")]
    cfgs = [c for c in ["B3_net_only", "EASA_no_energy", "EASA_full"] if c in df_lb["config"].unique()]
    lines, md = [], ["| Configuration | " + " | ".join(l for _, l, _ in cols) + " |", "|" + "---|" * (len(cols) + 1)]
    for c in cfgs:
        g = df_lb[df_lb["config"] == c]
        cells = []
        for m, _, fmt in cols:
            if m not in g.columns: cells.append("--"); continue
            v = g[m].astype(float)
            cells.append(f"${fmt.format(v.mean())}$" if v.std() == 0 else f"${fmt.format(v.mean())} \\pm {fmt.format(v.std())}$")
        lines.append(LABEL[c] + " & " + " & ".join(cells) + r" \\"); md.append(f"| {LABEL[c]} | " + " | ".join(x.replace("\\pm", "±").replace("$", "") for x in cells) + " |")
    tex = ("\\begin{table}[!t]\n\\caption{Low-battery scenario ($e_d\\sim U(0.10,0.35)$ at $t=0$), 30 seeds, mean $\\pm$ sample std. "
           "``EASA, no energy-aware action'' (\\texttt{EASA\\_no\\_energy} in the released configurations; ``EASA without the selector'' in the text) "
           "is full EASA with the deferral branch of Algorithm~\\ref{alg:easa} disabled, on the same "
           "seeds and battery draws, so the difference between the last two rows is the effect of the selector alone. No battery "
           "recharges in this scenario, so no deferred step-up is executed; a deferral is either cancelled (the device relaxed to "
           "$L_1$ first) or still pending at the end of the run. Residual energy averages over all devices, including mains-powered ones at 1.0.}\n"
           "\\label{tab:lowbattery}\n\\centering\\scriptsize\n\\setlength{\\tabcolsep}{3pt}\n\\widebox{\\begin{tabular}{l" + "c" * len(cols)
           + "}\n\\toprule\nConfiguration & " + " & ".join(l for _, l, _ in cols) + " \\\\\n\\midrule\n" + "\n".join(lines)
           + "\n\\bottomrule\n\\end{tabular}}\n\\end{table}\n")
    open(out_tex, "w").write(tex)
    return md


def reset_table(df_main, df_reset, out_tex, n_boot=2000):
    """Supplementary design revision: EASA with history reset vs EASA, paired over seeds (unadjusted p, exploratory)."""
    cols = [("f1_L2", "F1", "{:.3f}", True), ("fpr_L2", "FPR (clean)", "{:.3f}", False), ("fpr_L2_all_epochs", "Restricted share", "{:.3f}", False),
            ("post_attack_dwell_s", "Dwell (s)", "{:.0f}", False), ("false_quarantine_rate", "False quarantine", "{:.3f}", False),
            ("containment_rate", "Containment", "{:.3f}", True), ("cross_site_recall_L2", "Cross-site recall", "{:.3f}", True),
            ("replay_catch_rate", "Replay catch", "{:.3f}", True), ("reauth_per_device_hour", "Re-auth / dev-h", "{:.3f}", False)]
    a = df_main[df_main["config"] == "EASA_full"].sort_values("seed"); b = df_reset.sort_values("seed")
    if a.empty or b.empty: return []
    rng = np.random.default_rng(0); lines = []
    md = ["| Metric | EASA | EASA, history reset | Δ (reset − EASA) | 95% CI | p (unadjusted) |", "|---|---|---|---|---|---|"]
    for m, lab, fmt, hib in cols:
        x = a[m].to_numpy(float); y = b[m].to_numpy(float); d = y - x; d = d[~np.isnan(d)]
        p = 1.0 if np.allclose(d, 0) else stats.wilcoxon(d).pvalue
        boots = np.array([rng.choice(d, len(d)).mean() for _ in range(n_boot)]); lo, hi = np.percentile(boots, [2.5, 97.5])
        pstr = "$<0.001$" if p < 0.001 else f"{p:.3f}"
        dm = fmt.format(d.mean()); dm = ("$-$" + dm[1:]) if d.mean() < 0 else "+" + dm
        lines.append(f"{lab} & {fmt.format(np.nanmean(x))} $\\pm$ {fmt.format(np.nanstd(x, ddof=1))} & {fmt.format(np.nanmean(y))} $\\pm$ {fmt.format(np.nanstd(y, ddof=1))} & {dm} & $[{fmt.format(lo)}, {fmt.format(hi)}]$ & {pstr} \\\\")
        md.append(f"| {lab} | {np.nanmean(x):.3f} | {np.nanmean(y):.3f} | {d.mean():+.3f} | [{lo:.3f}, {hi:.3f}] | {pstr} |")
    nres = b["n_hist_resets"].mean() if "n_hist_resets" in b.columns else float("nan")
    tex = ("\\begin{table}[!t]\n\\caption{Supplementary design revision, not part of the pre-specified comparison: EASA with the history "
           "term reset to 1 after five consecutive restricted epochs whose network score is above $\\tau_{L1}$ "
           "(\\texttt{policy.history\\_reset\\_epochs}=5; " + f"{nres:.0f}" + " resets per run on average), against EASA on the same 30 seeds "
           "and the same Cloud Run service. $\\Delta$ is reset $-$ EASA with a 95\\% bootstrap CI and an unadjusted paired Wilcoxon $p$.}\n"
           "\\label{tab:reset}\n\\centering\\scriptsize\n\\setlength{\\tabcolsep}{4pt}\n\\widebox{\\begin{tabular}{lccccc}\n\\toprule\n"
           "Metric & EASA & EASA, history reset & $\\Delta$ & 95\\% CI & $p$ \\\\\n\\midrule\n" + "\n".join(lines)
           + "\n\\bottomrule\n\\end{tabular}}\n\\end{table}\n")
    open(out_tex, "w").write(tex)
    return md


# ----------------------------------------------------------------------------- figures
def _style_boxes(bp, cfgs):
    for patch, c in zip(bp["boxes"], cfgs):
        patch.set_facecolor(PALETTE[c]); patch.set_alpha(0.75); patch.set_edgecolor("#333"); patch.set_linewidth(0.6)
        if c in HATCH: patch.set_hatch(HATCH[c])
    for k in ["whiskers", "caps", "medians"]:
        for a in bp[k]: a.set_color("#333"); a.set_linewidth(0.7)
    for f in bp["fliers"]: f.set(marker="o", markersize=2.5, markerfacecolor="#333", markeredgecolor="none", alpha=0.6)


def fig_metrics(df, out):
    cfgs = _cfgs(df)
    fig, axes = plt.subplots(2, 3, figsize=(7.2, 4.6))
    for ax, (m, lab) in zip(axes.ravel(), BOX):
        data = [df[df["config"] == c][m].dropna().to_numpy() for c in cfgs]
        bp = ax.boxplot(data, patch_artist=True, widths=0.62, showmeans=False)
        _style_boxes(bp, cfgs)
        ax.set_xticks(range(1, len(cfgs) + 1)); ax.set_xticklabels([LABEL[c] for c in cfgs], rotation=35, ha="right", fontsize=7)
        ax.set_title(lab); ax.grid(axis="x", visible=False)
        if m == "fpr_L2":
            ax.axhline(0.02, color="#333", lw=0.6, ls="--")
            ax.text(0.02, 0.0215, "calibration target 2%", ha="left", va="bottom", fontsize=6, color="#333", transform=ax.get_yaxis_transform())
    fig.tight_layout(h_pad=1.2); fig.savefig(out); plt.close(fig)


def fig_family(piv, out):
    if piv is None: return
    fams = [f for f in piv.index if f not in ("FirmwareTamper",)]
    cfgs = [c for c in piv.columns if c != "B0_static"]; w = 0.8 / len(cfgs); x = np.arange(len(fams))   # B0 never escalates
    fig, ax = plt.subplots(figsize=(7.2, 2.8))
    for i, c in enumerate(cfgs):
        ax.bar(x + (i - (len(cfgs) - 1) / 2) * w, piv.loc[fams, c].values, w * 0.92, color=PALETTE[c], hatch=HATCH.get(c, ""),
               edgecolor="#333", linewidth=0.4, label=LABEL[c])
    ax.set_xticks(x); ax.set_xticklabels([f.replace("CredentialReplay", "Cred. replay") for f in fams])
    ax.set_ylabel("recall at $L_2$"); ax.set_ylim(0, 1.0); ax.grid(axis="x", visible=False)
    ax.legend(ncol=6, loc="upper center", bbox_to_anchor=(0.5, 1.18), frameon=False)
    fig.tight_layout(); fig.savefig(out); plt.close(fig)


def fig_cross_site(df, out):
    cfgs = [c for c in _cfgs(df) if c != "B0_static"]
    fig, ax = plt.subplots(figsize=(4.6, 3.0))
    for i, c in enumerate(cfgs):
        g = df[df["config"] == c]
        a, b = g["in_dist_recall_L2"].mean(), g["cross_site_recall_L2"].mean()
        ax.plot([i - 0.18, i + 0.18], [a, b], color=PALETTE[c], lw=1.6)
        ax.scatter([i - 0.18], [a], color=PALETTE[c], s=28, marker="o", zorder=3, edgecolor="#333", linewidth=0.5)
        ax.scatter([i + 0.18], [b], color=PALETTE[c], s=28, marker="s", zorder=3, edgecolor="#333", linewidth=0.5)
        ax.text(i + 0.26, b, f"{b:.2f}", va="center", fontsize=8)
    ax.set_xticks(range(len(cfgs))); ax.set_xticklabels([LABEL[c] for c in cfgs], rotation=35, ha="right", fontsize=8)
    ax.tick_params(axis="y", labelsize=8); ax.set_ylabel("recall at $L_2$", fontsize=9); ax.set_ylim(0, 1.0); ax.grid(axis="x", visible=False)
    ax.scatter([], [], marker="o", color="#333", s=20, label="in-distribution family"); ax.scatter([], [], marker="s", color="#333", s=20, label="held-out family (cross-site)")
    ax.legend(loc="upper left", frameon=False, fontsize=8)
    fig.tight_layout(); fig.savefig(out); plt.close(fig)


def fig_trust_trace(traces_dir, out, config="EASA_full"):
    """Three panels: a compromised device (L3 absorbing after the campaign), a benign device at the same gateway that
    recovered or was never restricted, and the benign device with the longest restricted dwell that never recovered
    (the L2 lock-in of Sec. 5.7), if one exists."""
    files = glob.glob(os.path.join(traces_dir, f"{config}_seed*.parquet")) + glob.glob(os.path.join(traces_dir, f"{config}_seed*.csv.gz"))
    if not files: return
    df = pd.read_parquet(files[0]) if files[0].endswith(".parquet") else pd.read_csv(files[0])
    att = df[df["attacking"] & ~df["family"].isin(["CredentialReplay", "FirmwareTamper"])].groupby("device").size()
    if att.empty: return
    dev = att.idxmax(); gw = df[df["device"] == dev]["gateway"].iloc[0]
    attacked = set(df[df["attacking"]]["device"])
    ben = df[~df["device"].isin(attacked)]
    # benign device stuck at >= L2 at the end of the run with the longest restricted time
    stuck = ben[ben["level"] >= 2].groupby("device").size()
    end_lv = ben.sort_values("t").groupby("device")["level"].last()
    stuck = stuck[[d for d in stuck.index if end_lv.get(d, 0) >= 2 and end_lv.get(d, 0) < 3]]
    stuck_dev = stuck.idxmax() if len(stuck) else None
    clean = [d for d in ben[ben["gateway"] == gw]["device"].unique() if d != stuck_dev]
    clean_dev = clean[0] if clean else None
    panels = [(dev, "compromised device: $L_3$ is absorbing after the first campaign")]
    if clean_dev is not None: panels.append((clean_dev, "benign device, same gateway"))
    if stuck_dev is not None: panels.append((stuck_dev, "benign device held at $L_2$ to the end of the run (history term at zero)"))
    fig, axes = plt.subplots(len(panels), 1, figsize=(7.2, 2.2 * len(panels)), sharex=True, squeeze=False)
    for ax, (d, title) in zip(axes[:, 0], panels):
        g = df[df["device"] == d].sort_values("t")
        ax.plot(g["t"], g["T"], color="#008300", lw=1.6, label="composite trust $T_d$")
        ax.plot(g["t"], g["S_net"], color="#2a78d6", lw=0.9, label="$S^{\\mathrm{net}}$")
        ax.plot(g["t"], g["S_pos"], color="#eda100", lw=0.9, label="$S^{\\mathrm{pos}}$")
        if "S_hist" in g.columns: ax.plot(g["t"], g["S_hist"], color="#7f3fbf", lw=0.9, ls="--", label="$S^{\\mathrm{hist}}$")
        ax.fill_between(g["t"], 0, g["level"] / 3.0, step="post", color="#e34948", alpha=0.12, label="security level (0--3, scaled)")
        att = g["attacking"].to_numpy(); tt = g["t"].to_numpy(); fams = []
        i = 0
        while i < len(att):                      # shade every campaign (contiguous attacking run) separately
            if att[i]:
                j = i
                while j + 1 < len(att) and att[j + 1]: j += 1
                ax.axvspan(tt[i], tt[j], color="#e34948", alpha=0.06, lw=0)
                fams.append(str(g["family"].iloc[i])); i = j + 1
            else:
                i += 1
        fam_ = ", ".join(dict.fromkeys(fams)) if fams else "none"
        ax.set_ylabel("score"); ax.set_title(f"{title} ({d}; campaign families: {fam_})", fontsize=8)
        ax.set_ylim(0, 1.05); ax.grid(axis="x", visible=False)
    axes[0, 0].legend(loc="lower left", ncol=5, frameon=False, fontsize=6.5); axes[-1, 0].set_xlabel("simulated time (s)")
    fig.tight_layout(); fig.savefig(out); plt.close(fig)


def fig_rtt(df, out):
    if "rtt_ms_p50" not in df.columns or df["rtt_ms_p50"].isna().all(): return
    d = df.dropna(subset=["rtt_ms_p50"]); cfgs = [c for c in ORDER if c in d["config"].unique()]
    fig, ax = plt.subplots(figsize=(4.2, 2.6))
    keys = [("rtt_ms_p50", "p50", 1.0), ("rtt_ms_p95", "p95", 0.65), ("rtt_ms_max", "max", 0.35)]
    w = 0.26
    for j, (k, lab, alpha) in enumerate(keys):
        vals = [d[d["config"] == c][k].mean() for c in cfgs]
        ax.bar(np.arange(len(cfgs)) + (j - 1) * w, vals, w * 0.92, color="#2a78d6", alpha=alpha, edgecolor="#333", linewidth=0.4, label=lab)
    ax.set_xticks(range(len(cfgs))); ax.set_xticklabels([LABEL[c] for c in cfgs]); ax.set_ylabel("round-trip time (ms)")
    ax.grid(axis="x", visible=False); ax.legend(frameon=False, ncol=3)
    fig.tight_layout(); fig.savefig(out); plt.close(fig)


def fig_outage(df_main, df_out, out):
    a = df_main[df_main["config"] == "EASA_full"]; b = df_out[df_out["config"] == "EASA_full"]
    if a.empty or b.empty: return
    mets = [("cross_site_recall_L2", "cross-site recall"), ("replay_catch_rate", "replay catch"), ("f1_L2", "F1"), ("fpr_L2", "FPR")]
    fig, axes = plt.subplots(1, len(mets), figsize=(7.2, 2.4))
    for ax, (m, lab) in zip(axes, mets):
        bp = ax.boxplot([a[m].dropna(), b[m].dropna()], patch_artist=True, widths=0.6)
        for patch, col in zip(bp["boxes"], ["#008300", "#e34948"]): patch.set_facecolor(col); patch.set_alpha(0.7); patch.set_edgecolor("#333")
        for k in ["whiskers", "caps", "medians"]:
            for art in bp[k]: art.set_color("#333")
        ax.set_xticks([1, 2]); ax.set_xticklabels(["cloud up", "900 s outage"]); ax.set_title(lab); ax.grid(axis="x", visible=False)
    fig.tight_layout(); fig.savefig(out); plt.close(fig)


AXIS_LABEL = {"w_net": "$w_{\\mathrm{net}}$", "beta": "$\\beta$", "h": "$h$ (epochs)", "k": "$k$ (top-$k$)", "target_fpr": "target FPR"}


def sensitivity_table(df_s, out_tex):
    if "axis" not in df_s.columns: return []
    mets = [("f1_L2", "F1"), ("fpr_L2", "FPR"), ("cross_site_recall_L2", "Cross-site"), ("containment_rate", "Contain."),
            ("fpr_L2_all_epochs", "Restricted share"), ("reauth_per_device_hour", "Re-auth/dev-h")]
    cfgs = [c for c in ["B3_net_only", "EASA_full"] if c in df_s["config"].unique()]
    g = df_s.groupby(["axis", "value", "config"])[[m for m, _ in mets]].mean()
    lines, md = [], ["| axis | value | " + " | ".join(f"{lab} {LABEL[c]}" for lab in [l for _, l in mets] for c in cfgs) + " |"]
    for axis in dict.fromkeys(df_s["axis"]):
        vals = sorted(df_s[df_s["axis"] == axis]["value"].unique())
        for i, v in enumerate(vals):
            cells = []
            for m, _ in mets:
                for c in cfgs:
                    cells.append(f"{g.loc[(axis, v, c), m]:.3f}")
            vs = f"{v:g}"
            lines.append((AXIS_LABEL.get(axis, axis) if i == 0 else "") + f" & {vs} & " + " & ".join(cells) + r" \\")
            md.append(f"| {axis} | {vs} | " + " | ".join(cells) + " |")
        lines.append(r"\midrule")
    lines = lines[:-1]
    head1 = "Axis & Value & " + " & ".join(f"\\multicolumn{{{len(cfgs)}}}{{c}}{{{lab}}}" for _, lab in mets) + r" \\"
    head2 = " & & " + " & ".join(LABEL[c] for _ in mets for c in cfgs) + r" \\"
    tex = ("\\begin{table}[!t]\n\\caption{Sensitivity analysis: one parameter varied at a time around the defaults "
           "($w_{\\mathrm{net}}=0.6$, $\\beta=0.7$, $h=5$, $k=3$, target FPR 2\\%), 10 seeds per point, in-process cloud mock "
           "(decision-equivalent to the deployed service). B3 has no fusion weights, so its rows under $w_{\\mathrm{net}}$ repeat the default run.}\n"
           "\\label{tab:sensitivity}\n\\centering\\scriptsize\n\\setlength{\\tabcolsep}{3pt}\n\\widebox{%\n\\begin{tabular}{ll" + "c" * (len(mets) * len(cfgs)) + "}\n\\toprule\n"
           + head1 + "\n" + head2 + "\n\\midrule\n" + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}}\n\\end{table}\n")
    open(out_tex, "w").write(tex)
    return md


def fig_sensitivity(df_s, out):
    if "axis" not in df_s.columns: return
    df_s = df_s[df_s["config"] == "EASA_full"] if "EASA_full" in df_s["config"].unique() else df_s
    axes_ = list(dict.fromkeys(df_s["axis"]))
    fig, axs = plt.subplots(1, len(axes_), figsize=(2.4 * len(axes_), 2.5), squeeze=False)
    for ax, axis in zip(axs[0], axes_):
        d = df_s[df_s["axis"] == axis]
        for m, lab, col in [("f1_L2", "F1", "#008300"), ("cross_site_recall_L2", "cross-site", "#2a78d6"), ("fpr_L2", "FPR", "#e34948")]:
            g = d.groupby("value")[m].agg(["mean", "std"]).sort_index()
            ax.errorbar(range(len(g)), g["mean"], yerr=g["std"], color=col, marker="o", ms=3, lw=1.2, capsize=2, label=lab)
            ax.set_xticks(range(len(g))); ax.set_xticklabels([str(v) for v in g.index], fontsize=7)
        ax.set_title(AXIS_LABEL.get(axis, axis)); ax.set_ylim(0, 1); ax.grid(axis="x", visible=False)
    axs[0][0].legend(frameon=False); axs[0][0].set_ylabel("EASA, mean over 10 seeds")
    fig.tight_layout(); fig.savefig(out); plt.close(fig)


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv"); ap.add_argument("--traces", default="results/traces"); ap.add_argument("--out", default="figures")
    ap.add_argument("--outage", default=None); ap.add_argument("--sens", default=None)
    ap.add_argument("--lowbattery", default=None); ap.add_argument("--reset", default=None, help="CSV with EASA_reset runs (supplementary)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    df = pd.read_csv(a.csv)
    md = ["# Results summary", f"source: {a.csv}, {len(df)} runs, {df['seed'].nunique()} seeds", ""]
    md += ["## Main table"] + results_table(df, os.path.join(a.out, "tab_results.tex")) + [""]
    fam_md, piv = family_table(df, os.path.join(a.out, "tab_family.tex"))
    md += ["## Per-family recall"] + fam_md + [""]
    md += ["## Calibrated thresholds"] + threshold_table(df, os.path.join(a.out, "tab_thresholds.tex")) + [""]
    md += ["## Cloud calls"] + rtt_table(df, os.path.join(a.out, "tab_rtt.tex")) + [""]
    md += ["## Credential-replay denominators"] + replay_table(df, os.path.join(a.out, "tab_replay.tex")) + [""]
    md += ["## Benign-side cost"] + benign_table(df, os.path.join(a.out, "tab_benign.tex")) + [""]
    ep = episode_table(df, os.path.join(a.out, "tab_episodes.tex"))
    if ep: md += ["## Restriction activation decomposition"] + ep + [""]
    md += ["## Paired differences vs EASA_full (mean, bootstrap CI, Holm p)"] + paired_table(df, os.path.join(a.out, "tab_paired.tex")) + [""]
    md += ["## Significance (paired Wilcoxon vs EASA_full, Holm)"] + significance(df, os.path.join(a.out, "significance.txt"))
    fig_metrics(df, os.path.join(a.out, "fig_metrics.pdf"))
    fig_family(piv, os.path.join(a.out, "fig_family.pdf"))
    fig_cross_site(df, os.path.join(a.out, "fig_cross_site.pdf"))
    fig_trust_trace(a.traces, os.path.join(a.out, "fig_trust_trace.pdf"))
    fig_rtt(df, os.path.join(a.out, "fig_rtt.pdf"))
    if a.outage and os.path.exists(a.outage):
        fig_outage(df, pd.read_csv(a.outage), os.path.join(a.out, "fig_outage.pdf"))
    if a.sens and os.path.exists(a.sens):
        ds = pd.read_csv(a.sens)
        fig_sensitivity(ds, os.path.join(a.out, "fig_sensitivity.pdf"))
        md += ["", "## Sensitivity"] + sensitivity_table(ds, os.path.join(a.out, "tab_sensitivity.tex"))
    if a.lowbattery and os.path.exists(a.lowbattery):
        md += ["", "## Low-battery scenario"] + lowbattery_table(pd.read_csv(a.lowbattery), os.path.join(a.out, "tab_lowbattery.tex"))
    if a.reset and os.path.exists(a.reset):
        md += ["", "## Supplementary: history reset"] + reset_table(df, pd.read_csv(a.reset), os.path.join(a.out, "tab_reset.tex"))
    open(os.path.join(a.out, "summary.md"), "w").write("\n".join(md) + "\n")
    try:   # one-line captions (paper style); definitions live in the text
        from shorten_captions import shorten
        for f in glob.glob(os.path.join(a.out, "tab_*.tex")):
            t, n = shorten(open(f).read())
            if n: open(f, "w").write(t)
    except ImportError:
        pass
    print("\n".join(md)); print("\nwrote", sorted(os.listdir(a.out)))


if __name__ == "__main__":
    main()
