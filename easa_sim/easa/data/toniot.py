"""TON_IoT loaders (Moustafa 2021).

Scenario B uses the *network* file (Train_Test_Network.csv), which has real
src_ip and ts columns, so devices and time are taken from the data rather than
emulated. The *telemetry* files (Train_Test_IoT_Fridge.csv, ..._Thermostat.csv,
...) are used only to calibrate posture-model rates (beacon period, missing
ratio) per device class -- see posture.py:calibrate_from_toniot.
"""
from __future__ import annotations

import glob
import logging

import numpy as np
import pandas as pd

from .pool import BENIGN, FlowPool, dedup_rows, make_splits, scale_fit_transform

log = logging.getLogger(__name__)

# TON_IoT 'type' -> EASA family names (aligned with CIC-IoT-2023 where possible)
TYPE_MAP = {"normal": BENIGN, "ddos": "DDoS", "dos": "DoS", "scanning": "Recon",
            "mitm": "Spoofing", "xss": "Web", "injection": "Web", "backdoor": "Web",
            "password": "BruteForce", "ransomware": "Web"}

NUMERIC_HINTS = ["duration", "src_bytes", "dst_bytes", "missed_bytes", "src_pkts", "src_ip_bytes",
                 "dst_pkts", "dst_ip_bytes", "src_port", "dst_port"]


def load_toniot_network(cfg: dict, rng: np.random.Generator) -> FlowPool:
    path = cfg["data"]["toniot_network_csv"]
    df = pd.read_csv(path, low_memory=False)
    fam = df["type"].astype(str).str.lower().map(TYPE_MAP).fillna("Other").to_numpy().astype(str)
    keep = fam != "Other"
    df, fam = df[keep].reset_index(drop=True), fam[keep]
    y = (fam != BENIGN).astype(np.int8)
    cols = [c for c in NUMERIC_HINTS if c in df.columns]
    X = df[cols].apply(pd.to_numeric, errors="coerce").fillna(0).to_numpy(dtype=np.float32)
    # keep identity/time for scenario B replay
    meta = {
        "src_ip": df["src_ip"].astype(str).to_numpy() if "src_ip" in df else None,
        "ts": pd.to_numeric(df["ts"], errors="coerce").to_numpy() if "ts" in df else None,
    }
    X, y, fam, dup = dedup_rows(X, y, fam) if cfg["data"].get("dedup", True) else (X, y, fam, 0.0)
    tr, va, te = make_splits(rng, len(y), cfg["data"]["test_fraction"], cfg["data"]["val_fraction"], fam)
    Xs = scale_fit_transform(X, tr, cfg["data"].get("scale", "log_standard"))
    pool = FlowPool(Xs, y, fam, cols, tr, va, te,
                    rules_meta={"cols": {c: i for i, c in enumerate(cols)}, "raw_mu": X[tr].mean(0),
                                "raw_sd": X[tr].std(0) + 1e-6, "dup_ratio": dup, "replay_meta": meta})
    log.info(pool.summary())
    return pool


def load_toniot_telemetry(pattern: str) -> dict[str, pd.DataFrame]:
    """Return {device_type: dataframe} for the telemetry files matching the glob."""
    out = {}
    for f in sorted(glob.glob(pattern)):
        name = f.split("Train_Test_IoT_")[-1].replace(".csv", "").lower()
        out[name] = pd.read_csv(f, low_memory=False)
    return out
