"""Metrics (Section 3.8 / Section 5): detection F1 at the L2 boundary, false
quarantine rate, time-to-containment, overhead, cross-site detection."""
from __future__ import annotations

import numpy as np
import pandas as pd

COLS = ["t", "attacking", "family", "p_attack", "S_net", "S_pos", "S_hist", "T", "level", "reauth",
        "deferred_stepup", "e", "u", "q", "iota", "n_flows"]


def frames_from_gateways(gateways) -> pd.DataFrame:
    rows = []
    for g in gateways:
        for d in g.devices:
            df = pd.DataFrame(d.log_rows, columns=COLS)
            df["gateway"] = g.name; df["device"] = d.did; df["dclass"] = d.dclass.name
            df["holdout_family"] = df["family"].isin(g.holdout)
            rows.append(df)
    return pd.concat(rows, ignore_index=True)


def summarise(df: pd.DataFrame, epoch_s: float, sim_duration_s: float) -> dict:
    out = {}
    # --- detection at the L2 boundary (per epoch-device). Negatives = epochs of devices that are never
    #     attacked in this run; the post-attack dwell of a compromised device (hysteresis / L3 timer) is
    #     deliberate containment, not a false positive, and is reported separately as post_attack_dwell_s.
    ever = df.groupby("device")["attacking"].transform("max").astype(bool)
    y = df["attacking"].astype(int).to_numpy()
    yhat = (df["level"] >= 2).astype(int).to_numpy()
    clean = (~ever).to_numpy()
    tp = int(((y == 1) & (yhat == 1)).sum()); fn = int(((y == 1) & (yhat == 0)).sum())
    fp = int((clean & (yhat == 1)).sum()); tn = int((clean & (yhat == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    out["precision_L2"] = prec; out["recall_L2"] = rec
    out["f1_L2"] = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    out["fpr_L2"] = fp / (fp + tn) if fp + tn else 0.0
    fp_all = int(((y == 0) & (yhat == 1)).sum()); tn_all = int(((y == 0) & (yhat == 0)).sum())
    out["fpr_L2_all_epochs"] = fp_all / (fp_all + tn_all) if fp_all + tn_all else 0.0
    dwell = df[ever.to_numpy() & (y == 0) & (yhat == 1)]
    out["post_attack_dwell_s"] = float(len(dwell) * epoch_s / max(1, df.loc[ever.to_numpy(), "device"].nunique()))

    # --- false-quarantine rate: benign devices that ever reached L3
    per_dev = df.groupby("device").agg(ever_attacked=("attacking", "max"), max_level=("level", "max"))
    benign_dev = per_dev[per_dev["ever_attacked"] == 0]
    out["false_quarantine_rate"] = float((benign_dev["max_level"] == 3).mean()) if len(benign_dev) else 0.0
    out["n_benign_devices"] = int(len(benign_dev))

    # --- time-to-containment per attack episode (device-level contiguous attacking spans)
    ttcs, contained = [], 0; episodes = 0; pre_restricted = 0; ttcs_new = []
    for dev, g in df.groupby("device"):
        a = g["attacking"].to_numpy(); lv = g["level"].to_numpy(); t = g["t"].to_numpy()
        i = 0
        while i < len(a):
            if a[i]:
                j = i
                while j < len(a) and a[j]: j += 1
                episodes += 1
                hit = np.flatnonzero(lv[i:j] >= 2)
                if len(hit):
                    ttcs.append(t[i + hit[0]] - t[i]); contained += 1
                    if hit[0] == 0 and i > 0 and lv[i - 1] >= 2:   # already restricted when the episode began
                        pre_restricted += 1
                    else:
                        ttcs_new.append(t[i + hit[0]] - t[i])
                i = j
            else:
                i += 1
    out["n_attack_episodes"] = episodes
    out["containment_rate"] = contained / episodes if episodes else 0.0
    # decomposition (review round 2): restricted before onset (carried over from an earlier episode / L3 absorbing) vs
    # newly restricted during the episode; TTC over newly restricted episodes only
    out["containment_pre_restricted_rate"] = pre_restricted / episodes if episodes else 0.0
    out["containment_new_rate"] = (contained - pre_restricted) / episodes if episodes else 0.0
    out["ttc_new_p50_s"] = float(np.median(ttcs_new)) if ttcs_new else float("nan")
    out["ttc_mean_s"] = float(np.mean(ttcs)) if ttcs else float("nan")
    out["ttc_p50_s"] = float(np.median(ttcs)) if ttcs else float("nan")
    out["ttc_p95_s"] = float(np.percentile(ttcs, 95)) if ttcs else float("nan")

    # --- overhead
    dev_hours = df["device"].nunique() * sim_duration_s / 3600.0
    out["reauth_per_device_hour"] = float(df["reauth"].sum() / dev_hours)
    out["deferred_stepups"] = int(df["deferred_stepup"].sum())
    out["energy_final_mean"] = float(df.groupby("device")["e"].last().mean())
    # --- recall split: families the local detector was trained on (in-distribution) vs. held-out families (cross-site)
    ho = df[df["holdout_family"] & df["attacking"]]
    ind = df[~df["holdout_family"] & df["attacking"] & ~df["family"].isin(["CredentialReplay", "FirmwareTamper"])]
    out["cross_site_recall_L2"] = float((ho["level"] >= 2).mean()) if len(ho) else float("nan")
    out["in_dist_recall_L2"] = float((ind["level"] >= 2).mean()) if len(ind) else float("nan")
    out["n_holdout_epochs"] = int(len(ho)); out["n_in_dist_epochs"] = int(len(ind))
    att = df[df["attacking"]]
    out["recall_by_family"] = " ".join(f"{fam}={(g['level'] >= 2).mean():.2f}" for fam, g in att.groupby("family"))
    # --- credential replay: fraction of replay epochs caught (only the cloud revocation path can do this)
    rp = df[(df["family"] == "CredentialReplay") & df["attacking"]]
    out["replay_catch_rate"] = float((rp["level"] >= 3).mean()) if len(rp) else float("nan")
    out["n_replay_epochs"] = int(len(rp))
    return out


def bootstrap_ci(values: np.ndarray, rng: np.random.Generator, n: int = 2000, alpha: float = 0.05) -> tuple[float, float]:
    values = values[~np.isnan(values)]
    if len(values) == 0: return (float("nan"), float("nan"))
    bs = np.array([rng.choice(values, size=len(values), replace=True).mean() for _ in range(n)])
    return float(np.percentile(bs, 100 * alpha / 2)), float(np.percentile(bs, 100 * (1 - alpha / 2)))
