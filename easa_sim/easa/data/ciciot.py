"""CIC-IoT-2023 loader (Neto et al., Sensors 2023).

Expected layout: <ciciot_dir>/part-*.csv  (the 169 feature CSVs, 46 features + 'label').
Loading is chunked and stratified so that 4M rows fit comfortably in 32 GB RAM.

Label -> family mapping follows the dataset's 7 attack classes. The 34 fine-grained
labels are collapsed to the family prefix (e.g. 'DDoS-ICMP_Flood' -> 'DDoS').
"""
from __future__ import annotations

import glob
import logging
import os

import numpy as np
import pandas as pd

from .pool import BENIGN, FlowPool, dedup_rows, make_splits, scale_fit_transform

log = logging.getLogger(__name__)

FAMILY_PREFIX = {
    "DDoS": "DDoS", "DoS": "DoS", "Mirai": "Mirai", "Recon": "Recon",
    "Spoofing": "Spoofing", "MITM": "Spoofing",            # ARP spoofing / MITM grouped as Spoofing
    "Web": "Web", "XSS": "Web", "SqlInjection": "Web", "CommandInjection": "Web",
    "Backdoor_Malware": "Web", "BrowserHijacking": "Web", "Uploading_Attack": "Web",
    "BruteForce": "BruteForce", "DictionaryBruteForce": "BruteForce",
    "BenignTraffic": BENIGN, "Benign": BENIGN,
}

# Columns the rule-based detector (B2) uses as freshness/context proxies.
RULE_COLS = ["Rate", "Srate", "syn_count", "rst_count", "IAT", "Number", "Tot sum"]


def _family_of(label: str) -> str:
    head = str(label).split("-")[0]
    return FAMILY_PREFIX.get(head, FAMILY_PREFIX.get(str(label), "Other"))


def load_ciciot(cfg: dict, rng: np.random.Generator) -> FlowPool:
    d = cfg["data"]
    files = sorted(glob.glob(os.path.join(d["ciciot_dir"], "part-*.csv")))
    if not files:
        raise FileNotFoundError(f"no part-*.csv under {d['ciciot_dir']}. "
                                "Download CIC-IoT-2023 CSVs from the CIC website and place them there.")
    max_rows = int(d["max_rows"])
    per_file = max(1, max_rows // len(files))
    frames = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        if len(df) > per_file:
            # stratified within file: keep all minority classes, downsample the rest
            df["_fam"] = df["label"].map(_family_of)
            parts = []
            quota = per_file // max(1, df["_fam"].nunique())
            for fam, g in df.groupby("_fam"):
                parts.append(g if len(g) <= quota else g.sample(quota, random_state=int(rng.integers(1 << 31))))
            df = pd.concat(parts, ignore_index=True)
        else:
            df["_fam"] = df["label"].map(_family_of)
        frames.append(df)
        log.debug("loaded %s -> %d rows", os.path.basename(f), len(df))
    df = pd.concat(frames, ignore_index=True)
    df = df[df["_fam"] != "Other"]
    fam = df["_fam"].to_numpy().astype(str)
    y = (fam != BENIGN).astype(np.int8)
    feat_cols = [c for c in df.columns if c not in ("label", "_fam")]
    X = df[feat_cols].to_numpy(dtype=np.float32)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    dup_ratio = 0.0
    if d.get("dedup", True):
        X, y, fam, dup_ratio = dedup_rows(X, y, fam)

    tr, va, te = make_splits(rng, len(y), d["test_fraction"], d["val_fraction"], fam)
    rule_idx = {c: feat_cols.index(c) for c in RULE_COLS if c in feat_cols}
    Xs = scale_fit_transform(X, tr, cfg["data"].get("scale", "log_standard"))
    pool = FlowPool(Xs, y, fam, feat_cols, tr, va, te,
                    rules_meta={"cols": rule_idx, "raw_mu": X[tr].mean(0), "raw_sd": X[tr].std(0) + 1e-6,
                                "dup_ratio": dup_ratio})
    log.info(pool.summary())
    return pool
