"""CIC IoT-DIAD 2024 loader -- "Anomaly Detection - Flow Based features" (CICFlowMeter CSVs).

Layout (as downloaded by scripts/download_iotdiad.py):
    <iotdiad_dir>/<Family>/<Attack name>/*.csv   Family in {Benign, BruteForce, DDoS, DoS, Mirai, Recon, Spoofing, Web-Based}

Facts established by scripts/inspect_iotdiad.py on the full data (2026-10-07):
  * Rows are NOT labelled individually (README); attack captures are whole-LAN pcaps and contain
    benign background traffic.  -> row-level labelling rule below (label_mode = dominant_src).
  * The LAN is a DHCP range (192.168.137.0/24): IPs are stable *within* a capture chain but are
    re-assigned between capture sessions (Aug 2022 .. Feb 2023).  -> device identity is per-capture;
    the attacking Raspberry Pis are themselves listed devices, so attackers also appear in Benign.
  * 68 in-subnet device IPs in the Benign chain (4 contiguous files, ~28 h).
  * DoS-TCP_Flood files are headerless and contain one row each -> dropped.

Row-level labelling (dominant_src): for each attack type, in-subnet Src IPs are ranked by flow count;
IPs with share >= min_share (default 5 %) up to max_attackers (8) are the attackers.  A row is an
attack iff Src or Dst is an attacker.  If the attackers' cumulative share < weak_threshold (40 %)
the type is flagged *weak* and capture-level labels are used (reported separately in the paper).
"""
from __future__ import annotations

import glob
import ipaddress
import json
import logging
import os
import re
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

from .pool import BENIGN, FlowPool, scale_fit_transform

log = logging.getLogger(__name__)

FAMILY_DIR = {"Benign": BENIGN, "BruteForce": "BruteForce", "DDoS": "DDoS", "DoS": "DoS", "Mirai": "Mirai",
              "Recon": "Recon", "Spoofing": "Spoofing", "Web-Based": "Web", "Web": "Web"}
META_COLS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp", "Label"]
RULE_COLS = ["Flow Packets/s", "Fwd Packets/s", "SYN Flag Count", "RST Flag Count", "Flow IAT Mean", "Total Fwd Packet"]
REQUIRED = ["Src IP", "Dst IP", "Timestamp"]
CANON_COLS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp", "Flow Duration",
              "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet", "TotalLength of Bwd Packet",
              "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
              "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
              "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
              "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
              "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
              "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s",
              "Bwd Packets/s", "Packet Length Min", "Packet Length Max", "Packet Length Mean", "Packet Length Std",
              "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
              "ACK Flag Count", "URG Flag Count", "CWR Flag Count", "ECE Flag Count", "Down/Up Ratio",
              "Average Packet Size", "Fwd Segment Size Avg", "Bwd Segment Size Avg", "Fwd Bytes/Bulk Avg",
              "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg", "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg",
              "Bwd Bulk Rate Avg", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
              "Subflow Bwd Bytes", "FWD Init Win Bytes", "Bwd Init Win Bytes", "Fwd Act Data Pkts",
              "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std",
              "Idle Max", "Idle Min", "Label"]
_FLOWID_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}-\d+-\d+-\d+$")


# ----------------------------------------------------------------------------- CSV helpers
def is_headerless(path: str) -> bool:
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        first = f.readline().split(",")[0].strip()
    return bool(_FLOWID_RE.match(first))


def normalise_columns(cols) -> dict[str, str]:
    canon = {c.lower().replace(" ", ""): c for c in CANON_COLS}
    return {raw: canon.get(str(raw).strip().lower().replace(" ", ""), str(raw).strip()) for raw in cols}


def read_header(path: str) -> list[str]:
    if is_headerless(path):
        n = len(pd.read_csv(path, nrows=1, header=None).columns)
        return CANON_COLS[:n] if n <= len(CANON_COLS) else CANON_COLS + [f"extra{i}" for i in range(n - len(CANON_COLS))]
    return list(pd.read_csv(path, nrows=0, encoding="utf-8-sig").columns)


def read_csv_canon(path: str, usecols: list[str] | None = None, nrows: int | None = None, start_row: int = 0) -> pd.DataFrame:
    """Read [start_row, start_row+nrows) data rows with canonical column names (fast C-parser skipping)."""
    if is_headerless(path):
        hdr = read_header(path)
        df = pd.read_csv(path, header=None, names=hdr, nrows=nrows, low_memory=False, usecols=usecols or None,
                         skiprows=start_row or None)
    else:
        raw = list(pd.read_csv(path, nrows=0, encoding="utf-8-sig").columns)
        cmap = normalise_columns(raw); inv = {v: k for k, v in cmap.items()}
        use = [inv[c] for c in usecols if c in inv] if usecols else None
        df = pd.read_csv(path, header=None, names=raw, usecols=use, nrows=nrows, low_memory=False, encoding="utf-8-sig",
                         skiprows=1 + start_row)
        df.columns = [cmap.get(c, str(c).strip()) for c in df.columns]
    return df


def read_windows(path: str, windows: list[tuple[int, int]]) -> pd.DataFrame:
    """Concatenate several contiguous row windows [(start, n), ...] of one file."""
    return pd.concat([read_csv_canon(path, nrows=n, start_row=s) for s, n in windows], ignore_index=True)


def count_rows(path: str) -> int:
    with open(path, "rb") as f:
        n = sum(1 for _ in f)
    return n - (0 if is_headerless(path) else 1)


def _parse_ts(s: pd.Series) -> pd.Series:
    return pd.to_datetime(s, format="mixed", dayfirst=True, errors="coerce")


def _in_subnet(ip: str, subnet: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False


# ----------------------------------------------------------------------------- file catalogue
def catalogue(root: str, min_rows: int = 100) -> list[dict]:
    files = sorted(glob.glob(os.path.join(root, "**", "*.csv"), recursive=True))
    out = []
    for f in files:
        rel = os.path.relpath(f, root).split(os.sep)
        fam = FAMILY_DIR.get(rel[0])
        if fam is None:
            log.warning("skip %s (unknown family folder %s)", f, rel[0]); continue
        attack = rel[1] if len(rel) > 2 else fam
        n = count_rows(f)
        if n < min_rows:
            log.warning("skip %s (%d rows < %d)", f, n, min_rows); continue
        out.append({"path": f, "family": fam, "attack": attack, "rows": n, "file": os.path.basename(f)})
    if not out:
        raise FileNotFoundError(f"no usable CSVs under {root}")
    return out


# ----------------------------------------------------------------------------- attacker sets
def attacker_sets(root: str, cat: list[dict], subnet: str, exclude: set[str], min_share: float, max_attackers: int,
                  weak_threshold: float, cache: str | None = None, pkt_types: tuple[str, ...] = ("ICMP", "Mirai")) -> dict[str, dict]:
    """Per attack type: {'attackers': [...], 'shares': {...}, 'cum': float, 'weak': bool}. Cached as JSON."""
    if cache and os.path.exists(cache):
        with open(cache) as f:
            d = json.load(f)
        if d.get("_params") == [subnet, sorted(exclude), min_share, max_attackers, weak_threshold, "v4-union", list(pkt_types)]:
            log.info("attacker sets loaded from cache %s", cache); return {k: v for k, v in d.items() if k != "_params"}
    log.info("computing attacker sets (one pass over Src IP / packet counts of every attack file) ...")
    flows: dict[str, Counter] = defaultdict(Counter)
    pkts: dict[str, Counter] = defaultdict(Counter)
    for e in cat:
        if e["family"] == BENIGN: continue
        df = read_csv_canon(e["path"], usecols=["Src IP", "Total Fwd Packet", "Total Bwd packets"])
        src = df["Src IP"].astype(str)
        npk = (pd.to_numeric(df.get("Total Fwd Packet", 0), errors="coerce").fillna(0).clip(lower=0) +
               pd.to_numeric(df.get("Total Bwd packets", 0), errors="coerce").fillna(0).clip(lower=0))
        flows[e["attack"]].update(src)
        pkts[e["attack"]].update(dict(npk.groupby(src).sum()))
    out = {}
    for attack in flows:
        f, p = flows[attack], pkts[attack]
        tf, tp = sum(f.values()), max(sum(p.values()), 1)
        cand = {ip for ip in f if _in_subnet(ip, subnet) and ip not in exclude}
        # Packet share is used only for flood types whose flows collapse under CICFlowMeter (ICMP has no
        # ports; Mirai greeth is GRE). For every other type the flow share is the measure -- packet share
        # there would promote chatty benign devices (cameras) to attackers.
        use_pkt = any(k.lower() in attack.lower() for k in pkt_types)
        fshare = {ip: f[ip] / tf for ip in cand}
        pshare = {ip: p.get(ip, 0) / tp for ip in cand}
        by_flow = [(ip, s) for ip, s in sorted(fshare.items(), key=lambda kv: -kv[1]) if s >= min_share][:max_attackers]
        if use_pkt:
            # flood types: union of packet-dominant and flow-dominant sources (bots score high on at least one)
            by_pkt = [(ip, s) for ip, s in sorted(pshare.items(), key=lambda kv: -kv[1]) if s >= min_share][:max_attackers]
            seen, att = set(), []
            for ip, _ in by_pkt + by_flow:
                if ip not in seen:
                    seen.add(ip); att.append((ip, max(fshare[ip], pshare[ip])))
            cum = float(sum(pshare[ip] for ip, _ in att)); top1 = max((pshare[ip] for ip, _ in att), default=0.0)
        else:
            att = by_flow
            cum = float(sum(s for _, s in att)); top1 = att[0][1] if att else 0.0
        weak = cum < weak_threshold and top1 < 0.25            # a single dominant source also counts as strong
        out[attack] = {"attackers": [ip for ip, _ in att], "measure": "packets" if use_pkt else "flows",
                       "shares": {ip: round(s, 4) for ip, s in att},
                       "flow_share": {ip: round(f[ip] / tf, 4) for ip, _ in att},
                       "pkt_share": {ip: round(p.get(ip, 0) / tp, 4) for ip, _ in att},
                       "cum": round(cum, 4), "top1": round(top1, 4), "weak": weak, "flows": tf, "packets": int(tp)}
        log.info("  %-26s [%s] attackers=%s cum=%.0f%% top1=%.0f%%%s", attack, "pkt" if use_pkt else "flow",
                 [ip for ip, _ in att], 100 * cum, 100 * top1, "  [WEAK -> capture labels]" if weak else "")
    if cache:
        with open(cache, "w") as f:
            json.dump({**out, "_params": [subnet, sorted(exclude), min_share, max_attackers, weak_threshold, "v4-union", list(pkt_types)]}, f, indent=1)
    return out


# ----------------------------------------------------------------------------- sampling
def _windows(n: int, quota: int, n_windows: int, rng: np.random.Generator) -> list[tuple[int, int]] | None:
    """`n_windows` non-overlapping contiguous windows totalling ~quota rows; None = take the whole file."""
    if quota >= n:
        return None
    w = max(1, quota // n_windows)
    # place windows in disjoint equal segments of the file so they never overlap
    seg = n // n_windows
    out = []
    for k in range(n_windows):
        lo, hi = k * seg, min((k + 1) * seg, n) - w
        if hi <= lo: continue
        out.append((int(rng.integers(lo, hi + 1)), w))
    return out or [(0, min(w, n))]


# ----------------------------------------------------------------------------- main loader
def load_iotdiad(cfg: dict, rng: np.random.Generator) -> FlowPool:
    d = cfg["data"]
    root = d["iotdiad_dir"]
    subnet = d.get("iotdiad_subnet", "192.168.137.0/24")
    exclude = set(d.get("iotdiad_exclude_ips", ["192.168.137.1"]))
    cat = catalogue(root, int(d.get("iotdiad_min_rows", 100)))

    # ---- attacker sets (full pass, cached)
    label_mode = d.get("iotdiad_label_mode", "dominant_src")
    att_sets = {}
    if label_mode == "dominant_src":
        att_sets = attacker_sets(root, cat, subnet, exclude, float(d.get("iotdiad_min_share", 0.05)),
                                 int(d.get("iotdiad_max_attackers", 8)), float(d.get("iotdiad_weak_threshold", 0.40)),
                                 cache=os.path.join(root, "iotdiad_attackers.json"),
                                 pkt_types=tuple(d.get("iotdiad_packet_share_types", ["ICMP", "Mirai"])))

    # ---- family-balanced quota, spread over files proportionally, contiguous windows
    max_rows = int(d["max_rows"]); n_windows = int(d.get("iotdiad_windows_per_file", 4))
    fams = sorted({e["family"] for e in cat})
    quota_fam = max_rows // len(fams)
    frames = []
    for fam in fams:
        entries = [e for e in cat if e["family"] == fam]
        tot = sum(e["rows"] for e in entries)
        for e in entries:
            q = int(quota_fam * e["rows"] / tot) if tot > quota_fam else e["rows"]
            win = _windows(e["rows"], max(q, 1000), n_windows, rng)
            df = read_csv_canon(e["path"]) if win is None else read_windows(e["path"], win)
            df = df[[c for c in CANON_COLS if c in df.columns]]
            df["_family"], df["_attack"], df["_file"] = fam, e["attack"], e["file"]
            frames.append(df)
            log.debug("%s: %d/%d rows", e["file"], len(df), e["rows"])
    df = pd.concat(frames, ignore_index=True); del frames

    # ---- metadata
    ts = _parse_ts(df["Timestamp"]); bad = ts.isna()
    if bad.any():
        log.warning("dropping %d rows with unparseable timestamps", int(bad.sum()))
        df, ts = df[~bad].reset_index(drop=True), ts[~bad].reset_index(drop=True)
    abs_t = (ts - pd.Timestamp("1970-01-01")).dt.total_seconds().to_numpy(dtype=np.float64)   # epoch seconds, resolution-safe
    src, dst = df["Src IP"].astype(str).to_numpy(), df["Dst IP"].astype(str).to_numpy()
    fam = df["_family"].to_numpy().astype(str); attack = df["_attack"].to_numpy().astype(str)
    fileid = df["_file"].to_numpy().astype(str)
    is_attack_capture = fam != BENIGN

    # ---- device universe (Benign chain) & per-row device id (valid within the Benign chain only)
    benign_src = pd.Series(src[~is_attack_capture])
    device_ips = sorted({ip for ip in benign_src.unique() if _in_subnet(ip, subnet) and ip not in exclude},
                        key=lambda s: tuple(int(p) for p in s.split(".")))
    dev_index = {ip: i for i, ip in enumerate(device_ips)}
    src_dev = np.array([dev_index.get(ip, -1) for ip in src], dtype=np.int32)
    dst_dev = np.array([dev_index.get(ip, -1) for ip in dst], dtype=np.int32)
    device = np.where(~is_attack_capture, np.where(src_dev >= 0, src_dev, dst_dev), -1)

    # ---- row labels
    weak_types = set()
    weak_policy = d.get("iotdiad_weak_policy", "drop")      # drop (main experiment) | capture (keep with capture labels)
    keep_mask = np.ones(len(df), dtype=bool)
    if label_mode == "capture":
        y = is_attack_capture.astype(np.int8)
    elif label_mode == "dominant_src":
        y = np.zeros(len(df), dtype=np.int8)
        attacker_of_row = np.full(len(df), "", dtype=object)
        for atk, info in att_sets.items():
            m = attack == atk
            if not m.any(): continue
            if info["weak"]:
                weak_types.add(atk)
                if weak_policy == "drop":
                    keep_mask[m] = False                  # excluded from training AND replay; reported as a limitation
                else:
                    y[m] = 1; attacker_of_row[m] = src[m] # capture-level: every source treated as attacker
                continue
            A = set(info["attackers"])
            s_in = np.array([ip in A for ip in src[m]]); d_in = np.array([ip in A for ip in dst[m]])
            hit = s_in | d_in
            y[np.flatnonzero(m)[hit]] = 1
            attacker_of_row[np.flatnonzero(m)[hit]] = np.where(s_in[hit], src[m][hit], dst[m][hit])
        fam = np.where(is_attack_capture & (y == 0), BENIGN, fam)   # background rows in attack captures -> benign
        log.info("dominant_src labelling: attack rows = %.1f%% of attack-capture rows; weak types=%s (%s)",
                 100 * y[is_attack_capture & keep_mask].mean(), sorted(weak_types), weak_policy)
    else:
        raise ValueError(label_mode)

    # ---- features
    feat_cols = [c for c in df.columns if c not in META_COLS and not c.startswith("_")]
    X = np.nan_to_num(df[feat_cols].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=np.float32), nan=0.0, posinf=0.0, neginf=0.0)
    # flow duration in seconds (CICFlowMeter reports microseconds), clipped to the 120 s flow timeout: the time at which a
    # completed flow record becomes observable is Timestamp (flow start) + duration (protocol v3, replay.availability=end)
    dur_s = (np.clip(X[:, feat_cols.index("Flow Duration")], 0.0, 120e6) / 1e6).astype(np.float64) if "Flow Duration" in feat_cols \
        else np.zeros(len(X))
    dur_raw_s = (X[:, feat_cols.index("Flow Duration")] / 1e6).astype(np.float64) if "Flow Duration" in feat_cols else np.zeros(len(X))   # unclipped, for the protocol audit
    del df
    if not keep_mask.all():
        log.info("dropping %d rows of weak-labelled attack types", int((~keep_mask).sum()))
        X, y, fam, attack, fileid, abs_t, src, dst, device, dur_s, dur_raw_s = (a[keep_mask] for a in (X, y, fam, attack, fileid, abs_t, src, dst, device, dur_s, dur_raw_s))
        if label_mode == "dominant_src":
            attacker_of_row = attacker_of_row[keep_mask]

    # ---- time-based split within each capture file (train 60 / val 10 / test 30 along the timeline)
    test_f, val_f = d["test_fraction"], d["val_fraction"]
    train, val, test = [], [], []
    for fid in np.unique(fileid):
        idx = np.flatnonzero(fileid == fid); order = idx[np.argsort(abs_t[idx], kind="stable")]
        n = len(order); n_tr = int(n * (1 - test_f - val_f)); n_va = int(n * val_f)
        train.append(order[:n_tr]); val.append(order[n_tr:n_tr + n_va]); test.append(order[n_tr + n_va:])
    tr, va, te = np.concatenate(train), np.concatenate(val), np.concatenate(test)

    dup_ratio = 0.0
    if d.get("dedup", True):
        _, first = np.unique(X[tr], axis=0, return_index=True)
        keep = np.zeros(len(tr), bool); keep[first] = True
        dup_ratio = 1.0 - keep.mean(); tr = tr[keep]
        log.info("dedup (train split): removed %.1f%% exact-duplicate rows", 100 * dup_ratio)

    rule_idx = {c: feat_cols.index(c) for c in RULE_COLS if c in feat_cols}
    Xs = scale_fit_transform(X, tr, cfg["data"].get("scale", "log_standard"))
    pool = FlowPool(Xs, y, fam, feat_cols, tr, va, te,
                    rules_meta={"cols": rule_idx, "raw_mu": X[tr].mean(0), "raw_sd": X[tr].std(0) + 1e-6, "dup_ratio": dup_ratio,
                                "replay_meta": {"device": device, "abs_t": abs_t, "dur_s": dur_s, "dur_raw_s": dur_raw_s, "src": src, "dst": dst, "attack": attack,
                                                "file": fileid, "device_ips": device_ips, "attacker_sets": att_sets,
                                                "attacker_of_row": attacker_of_row if label_mode == "dominant_src" else None,
                                                "weak_types": sorted(weak_types), "label_mode": label_mode}})
    log.info(pool.summary())
    log.info("IoT-DIAD: %d device IPs in %s (Benign chain)", len(device_ips), subnet)
    return pool
