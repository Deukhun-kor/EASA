"""TON_IoT loaders (Moustafa 2021).

Revision round 1 (Sensors, 2026-11): the timestamped *network* files (Processed_Network_dataset/Network_dataset_k.csv;
Train_Test_Network.csv is a random sample without `ts`) are used for a reduced replication
with INDEPENDENT, ROW-LEVEL GROUND-TRUTH LABELS. Every record carries `label` (0/1) and `type` (normal / ddos / dos /
scanning / mitm / xss / injection / backdoor / password / ransomware) assigned by the dataset authors from the attack
schedule, plus Zeek identity and time (src_ip, dst_ip, ts, duration). The loader therefore produces the same FlowPool
+ replay metadata as the IoT-DIAD loader (per-device benign traces, per-attacker attack traces, availability = ts +
duration), so the trace-replay protocol of the paper runs unchanged, and it supports two label modes:

  toniot_label_mode: truth         rows labelled by the dataset's own label column (ground truth);
                     dominant_src  rows labelled by the paper's dominant-source rule (min share / attacker cap /
                                   weakness test) applied to TON_IoT exactly as to IoT-DIAD, ignoring the label column.
Comparing the two gives (i) the accuracy of the dominant-source rule against ground truth (per type: precision /
recall of the designated attacker set and of the row labels; written to <out_dir>/toniot_label_check.json) and (ii)
whether the system-level results change when the detector is trained and the campaigns are built from rule labels
instead of true labels (run the grid once per mode).

The telemetry files (Train_Test_IoT_Fridge.csv, ...) are used only to calibrate posture-model rates (posture.py).
"""
from __future__ import annotations

import glob
import ipaddress
import json
import logging
import os
import re
from collections import Counter

import numpy as np
import pandas as pd

from .pool import BENIGN, FlowPool, scale_fit_transform

log = logging.getLogger(__name__)

# TON_IoT 'type' -> EASA family names (aligned with the IoT-DIAD families where possible)
TYPE_MAP = {"normal": BENIGN, "ddos": "DDoS", "dos": "DoS", "scanning": "Recon",
            "mitm": "Spoofing", "xss": "Web", "injection": "Web", "backdoor": "Web",
            "password": "BruteForce", "ransomware": "Web"}

# numeric Zeek conn features; ports are excluded (as in the IoT-DIAD feature set, which drops the CICFlowMeter
# identity columns) so that the detector cannot read the attack off a destination port
NUMERIC_COLS = ["duration", "src_bytes", "dst_bytes", "missed_bytes", "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes"]
CATEGORICAL_COLS = {"proto": ["tcp", "udp", "icmp"], "conn_state": ["S0", "SF", "REJ", "RSTO", "RSTR", "OTH", "S1", "SH"]}
RULE_COLS = ["src_pkts", "dst_pkts", "duration", "src_bytes"]


def _private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def dominant_src_sets(src: np.ndarray, atype: np.ndarray, is_attack_capture: np.ndarray, min_share: float,
                      max_attackers: int, weak_threshold: float, exclude: set[str]) -> dict[str, dict]:
    """The paper's dominant-source rule applied per attack type to TON_IoT rows (flow share only; TON_IoT has no
    packet-collapsed flood types in the IoT-DIAD sense)."""
    out = {}
    for t in sorted(set(atype[is_attack_capture])):
        m = is_attack_capture & (atype == t)
        cnt = Counter(src[m]); tot = sum(cnt.values())
        cand = {ip: c / tot for ip, c in cnt.items() if _private(ip) and ip not in exclude}
        att = [(ip, s) for ip, s in sorted(cand.items(), key=lambda kv: -kv[1]) if s >= min_share][:max_attackers]
        cum = float(sum(s for _, s in att)); top1 = att[0][1] if att else 0.0
        out[t] = {"attackers": [ip for ip, _ in att], "shares": {ip: round(s, 4) for ip, s in att}, "cum": round(cum, 4),
                  "top1": round(top1, 4), "weak": bool(cum < weak_threshold and top1 < 0.25), "flows": int(tot)}
    return out


def _network_files(d: dict) -> list[str]:
    """Files of the network dataset: `toniot_network_files` (a list of paths, or a glob string) or, failing that, the
    single `toniot_network_csv`. The replication uses the timestamped Processed_Network_dataset/Network_dataset_k.csv
    files (Train_Test_Network.csv carries no `ts`)."""
    files = d.get("toniot_network_files")
    if not files:
        return [d["toniot_network_csv"]]
    if isinstance(files, str):
        out = sorted(glob.glob(files), key=lambda f: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", os.path.basename(f))])
        if not out:
            raise FileNotFoundError(f"no TON_IoT network file matches {files}")
        return out
    return [str(f) for f in files]


_READ_COLS = ["ts", "src_ip", "dst_ip", "proto", "conn_state", "label", "type"] + NUMERIC_COLS


def _read_network(files: list[str], max_block: int) -> pd.DataFrame:
    """Read the network files (needed columns only) and cap every (file, attack type) block at `max_block` rows -- the
    chronologically first rows of the block, i.e. one contiguous captured segment per file and type, so that the
    per-attacker traces keep their real density. Normal rows are never capped. 0 = no cap."""
    parts = []
    for f in files:
        head = pd.read_csv(f, nrows=0).columns
        use = [c for c in _READ_COLS if c in head]
        df = pd.read_csv(f, usecols=use, low_memory=False)
        df["_file"] = os.path.splitext(os.path.basename(f))[0]
        t = df["type"].astype(str).str.lower()
        if max_block > 0:
            keep = np.ones(len(df), dtype=bool)
            ts = pd.to_numeric(df["ts"], errors="coerce").to_numpy()
            for ty in t.unique():
                if ty == "normal":
                    continue
                idx = np.flatnonzero((t == ty).to_numpy())
                if len(idx) > max_block:
                    order = idx[np.argsort(ts[idx], kind="stable")]
                    keep[order[max_block:]] = False
            df = df[keep]
        log.info("TON_IoT %s: %d rows kept (%s)", os.path.basename(f), len(df), ", ".join(f"{k}:{v}" for k, v in t[df.index].value_counts().items()))
        parts.append(df.reset_index(drop=True))
    return pd.concat(parts, ignore_index=True)


def load_toniot_network(cfg: dict, rng: np.random.Generator) -> FlowPool:
    d = cfg["data"]
    files = _network_files(d)
    df = _read_network(files, int(d.get("toniot_max_rows_per_block", 0)))
    path = ", ".join(os.path.basename(f) for f in files)
    need = ["src_ip", "dst_ip", "ts", "label", "type"]
    missing = [c for c in need if c not in df.columns]
    if missing:
        raise ValueError(f"{path}: missing columns {missing} (Train_Test_Network.csv has no ts; use Processed_Network_dataset/Network_dataset_*.csv)")
    atype = df["type"].astype(str).str.lower().to_numpy()
    fam_all = np.array([TYPE_MAP.get(t, "Other") for t in atype], dtype=object)
    keep = fam_all != "Other"
    df, atype, fam_all = df[keep].reset_index(drop=True), atype[keep], fam_all[keep].astype(str)
    src, dst = df["src_ip"].astype(str).to_numpy(), df["dst_ip"].astype(str).to_numpy()
    ts = pd.to_numeric(df["ts"], errors="coerce").to_numpy(dtype=np.float64)
    ok = np.isfinite(ts)
    if not ok.all():
        log.warning("dropping %d TON_IoT rows with unparseable ts", int((~ok).sum()))
        df, atype, fam_all, src, dst, ts = df[ok].reset_index(drop=True), atype[ok], fam_all[ok], src[ok], dst[ok], ts[ok]
    y_truth = pd.to_numeric(df["label"], errors="coerce").fillna(0).to_numpy(dtype=np.int8)
    is_attack_capture = atype != "normal"          # "capture" = the dataset's attack type (the schedule the labels come from)
    exclude = set(d.get("toniot_exclude_ips", []))

    # ---- the paper's dominant-source rule (computed in both label modes: it is the label *check* and, under
    #      iotdiad_attacker_hosts = drop (protocol v4), the label-hygiene step)
    rule = dominant_src_sets(src, atype, is_attack_capture, float(d.get("iotdiad_min_share", 0.05)),
                             int(d.get("iotdiad_max_attackers", 8)), float(d.get("iotdiad_weak_threshold", 0.40)), exclude)
    attacker_hosts = {ip for info in rule.values() for ip in info["attackers"]} if d.get("iotdiad_attacker_hosts", "keep") == "drop" else set()
    if attacker_hosts:
        drop_rows = (~is_attack_capture) & (np.isin(src, list(attacker_hosts)) | np.isin(dst, list(attacker_hosts)))
        log.info("TON_IoT label hygiene: dropping %d normal rows (%.1f%%) to/from designated attacker hosts %s",
                 int(drop_rows.sum()), 100 * drop_rows.sum() / max(1, (~is_attack_capture).sum()), sorted(attacker_hosts))
        k = ~drop_rows
        df, atype, fam_all, src, dst, ts, y_truth, is_attack_capture = (df[k].reset_index(drop=True), atype[k], fam_all[k], src[k], dst[k], ts[k], y_truth[k], is_attack_capture[k])

    # ---- device universe: private IPv4 source addresses of normal rows with enough records to replay
    min_dev_rows = int(d.get("toniot_min_device_rows", 200))
    ipv4_only = bool(d.get("toniot_device_ipv4_only", True))
    cnt = Counter(src[~is_attack_capture])
    device_ips = sorted([ip for ip, c in cnt.items() if _private(ip) and ip not in exclude and ip not in attacker_hosts
                         and c >= min_dev_rows and (not ipv4_only or ip.count(".") == 3)],
                        key=lambda s: tuple(int(p) for p in s.split(".")) if s.count(".") == 3 else (999,))
    dev_index = {ip: i for i, ip in enumerate(device_ips)}
    src_dev = np.array([dev_index.get(ip, -1) for ip in src], dtype=np.int32)
    dst_dev = np.array([dev_index.get(ip, -1) for ip in dst], dtype=np.int32)
    device = np.where(~is_attack_capture, np.where(src_dev >= 0, src_dev, dst_dev), -1)

    # ---- labels: truth (dataset) or the paper's dominant-source rule
    mode = str(d.get("toniot_label_mode", "truth"))
    truth_sets = {t: sorted(set(src[is_attack_capture & (atype == t) & (y_truth == 1)])) for t in rule}
    if mode == "truth":
        y = y_truth.copy()
        attacker_of_row = np.where(y == 1, src, "").astype(object)      # one replay trace per attacking source address
        weak_types: set[str] = set()
    elif mode == "dominant_src":
        y = np.zeros(len(df), dtype=np.int8); attacker_of_row = np.full(len(df), "", dtype=object)
        weak_types = {t for t, info in rule.items() if info["weak"]}
        for t, info in rule.items():
            if info["weak"]:
                continue
            A = set(info["attackers"]); m = is_attack_capture & (atype == t)
            s_in = np.isin(src, list(A)) & m; d_in = np.isin(dst, list(A)) & m
            hit = s_in | d_in
            y[hit] = 1; attacker_of_row[hit] = np.where(s_in[hit], src[hit], dst[hit])
    else:
        raise ValueError(mode)
    fam = np.where(is_attack_capture & (y == 0), BENIGN, fam_all)
    keep_mask = ~np.isin(atype, list(weak_types)) if (mode == "dominant_src" and d.get("iotdiad_weak_policy", "drop") == "drop") else np.ones(len(df), bool)

    # ---- label check: the rule against ground truth (written next to the results; reported in the paper)
    check = {"mode": mode, "types": {}}
    for t, info in rule.items():
        m = is_attack_capture & (atype == t)
        A, G = set(info["attackers"]), set(truth_sets[t])
        yr = (np.isin(src, list(A)) | np.isin(dst, list(A))) & m
        yt = (y_truth == 1) & m
        tp = int((yr & yt).sum()); fp = int((yr & ~yt).sum()); fn = int((~yr & yt).sum())
        check["types"][t] = {"family": TYPE_MAP.get(t, "Other"), "rows": int(m.sum()), "truth_attack_rows": int(yt.sum()),
                             "rule_attackers": sorted(A), "truth_sources": sorted(G)[:20], "n_truth_sources": len(G),
                             "attacker_set_precision": round(len(A & G) / len(A), 4) if A else None,
                             "attacker_set_recall": round(len(A & G) / len(G), 4) if G else None,
                             "row_precision": round(tp / (tp + fp), 4) if tp + fp else None,
                             "row_recall": round(tp / (tp + fn), 4) if tp + fn else None, "weak": info["weak"], "cum_share": info["cum"]}
    out_dir = cfg.get("experiment", {}).get("out_dir", "results")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "toniot_label_check.json"), "w") as f:
        json.dump(check, f, indent=1)
    log.info("TON_IoT dominant-source rule vs ground truth: " + "; ".join(
        f"{t}: set P/R {v['attacker_set_precision']}/{v['attacker_set_recall']} row P/R {v['row_precision']}/{v['row_recall']}"
        for t, v in check["types"].items()))

    # ---- features: numeric Zeek conn fields + one-hot proto / conn_state
    cols = [c for c in NUMERIC_COLS if c in df.columns]
    X = df[cols].apply(pd.to_numeric, errors="coerce").fillna(0).to_numpy(dtype=np.float32)
    feat = list(cols)
    for c, levels in CATEGORICAL_COLS.items():
        if c in df.columns:
            v = df[c].astype(str).str.lower() if c == "proto" else df[c].astype(str)
            for lv in levels:
                X = np.column_stack([X, (v == (lv.lower() if c == "proto" else lv)).to_numpy(dtype=np.float32)]); feat.append(f"{c}={lv}")
    # availability = ts + duration. TON_IoT's Zeek connection logs are not terminated at a flow timeout (durations up to
    # ~9e4 s), so no cap is applied by default: a record becomes visible only at its real end. toniot_duration_cap_s
    # (e.g. 120) reproduces the capped rule of the first revision draft and is NOT used in the paper.
    cap = d.get("toniot_duration_cap_s")
    dur_s = pd.to_numeric(df["duration"], errors="coerce").fillna(0).clip(lower=0).to_numpy(dtype=np.float64) if "duration" in df else np.zeros(len(df))
    if cap:
        dur_s = np.minimum(dur_s, float(cap))
    dur_raw_s = pd.to_numeric(df["duration"], errors="coerce").fillna(0).to_numpy(dtype=np.float64) if "duration" in df else np.zeros(len(df))
    fileid = (df["_file"].astype(str) + ":" + pd.Series(atype)).to_numpy(dtype=object).astype(str)   # one "capture" per (file, type) block
    if not keep_mask.all():
        log.info("dropping %d rows of weak-labelled types %s", int((~keep_mask).sum()), sorted(weak_types))
        X, y, fam, atype, fileid, ts, src, dst, device, dur_s, dur_raw_s, attacker_of_row, y_truth = (
            a[keep_mask] for a in (X, y, fam, atype, fileid, ts, src, dst, device, dur_s, dur_raw_s, attacker_of_row, y_truth))

    # ---- time-based split within each type (as in the IoT-DIAD loader: 60 / 10 / 30 along the timeline)
    test_f, val_f = d["test_fraction"], d["val_fraction"]
    train, val, test = [], [], []
    for fid in np.unique(fileid):
        idx = np.flatnonzero(fileid == fid); order = idx[np.argsort(ts[idx], kind="stable")]
        n = len(order); n_tr = int(n * (1 - test_f - val_f)); n_va = int(n * val_f)
        train.append(order[:n_tr]); val.append(order[n_tr:n_tr + n_va]); test.append(order[n_tr + n_va:])
    tr, va, te = np.concatenate(train), np.concatenate(val), np.concatenate(test)
    dup_ratio = 0.0
    if d.get("dedup", True):
        _, first = np.unique(X[tr], axis=0, return_index=True)
        k = np.zeros(len(tr), bool); k[first] = True; dup_ratio = 1.0 - k.mean(); tr = tr[k]
    rule_idx = {c: feat.index(c) for c in RULE_COLS if c in feat}
    Xs = scale_fit_transform(X, tr, d.get("scale", "log_standard"))
    pool = FlowPool(Xs, y, fam.astype(str), feat, tr, va, te,
                    rules_meta={"cols": rule_idx, "raw_mu": X[tr].mean(0), "raw_sd": X[tr].std(0) + 1e-6, "dup_ratio": dup_ratio,
                                "replay_meta": {"device": device, "abs_t": ts, "dur_s": dur_s, "dur_raw_s": dur_raw_s, "src": src, "dst": dst,
                                                "attack": atype, "file": fileid, "device_ips": device_ips, "attacker_sets": rule,
                                                "attacker_of_row": attacker_of_row, "weak_types": sorted(weak_types),
                                                "attacker_hosts_dropped": sorted(attacker_hosts),
                                                "label_mode": mode, "y_truth": y_truth, "label_check": check}})
    log.info(pool.summary())
    log.info("TON_IoT (%s): %d device IPs with >= %d normal records; label mode = %s", path, len(device_ips), min_dev_rows, mode)
    return pool


def load_toniot_telemetry(pattern: str) -> dict[str, pd.DataFrame]:
    """Return {device_type: dataframe} for the telemetry files matching the glob."""
    out = {}
    for f in sorted(glob.glob(pattern)):
        name = f.split("Train_Test_IoT_")[-1].replace(".csv", "").lower()
        out[name] = pd.read_csv(f, low_memory=False)
    return out
