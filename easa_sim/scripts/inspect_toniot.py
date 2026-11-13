#!/usr/bin/env python3
"""Dry run of the TON_IoT network file before the reduced replication (revision round 1).

  python scripts/inspect_toniot.py data/TON_IoT/Network_dataset_1.csv

Prints: columns, rows per type, time span per type, number of private-subnet source addresses in normal traffic and
how many have >= 200 records (= replayable devices), the dominant-source rule's designated attackers per type versus the
ground-truth attacking sources, and the duration distribution. Nothing is written.
"""
import sys
from collections import Counter

import numpy as np
import pandas as pd

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))
from easa.data.toniot import TYPE_MAP, _private, dominant_src_sets  # noqa: E402


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "data/TON_IoT/Train_Test_Network.csv"
    df = pd.read_csv(path, low_memory=False)
    print("rows", len(df), "columns", list(df.columns))
    if "ts" not in df.columns:
        print("\nThis file has no `ts` (timestamp) column, so it cannot be replayed as device traces. The TON_IoT "
              "Train_Test_Network.csv is a random sample without timestamps; the timestamped records are in "
              "Processed_datasets/Processed_Network_dataset/Network_dataset_*.csv (23 files). Use those (or a few of them) instead.")
        print("rows per type:", df["type"].astype(str).str.lower().value_counts().to_dict())
        return
    atype = df["type"].astype(str).str.lower().to_numpy()
    ts = pd.to_numeric(df["ts"], errors="coerce")
    print("\nrows / time span per type:")
    for t, g in df.groupby(atype):
        tt = ts[g.index]
        print(f"  {t:12s} {len(g):8d}  {pd.to_datetime(tt.min(), unit='s')} .. {pd.to_datetime(tt.max(), unit='s')}  family={TYPE_MAP.get(t, 'Other')}")
    src = df["src_ip"].astype(str).to_numpy(); dst = df["dst_ip"].astype(str).to_numpy()
    normal = atype == "normal"
    cnt = Counter(src[normal]); priv = {ip: c for ip, c in cnt.items() if _private(ip)}
    print(f"\nnormal traffic: {len(cnt)} source addresses, {len(priv)} private; with >= 200 records: {sum(c >= 200 for c in priv.values())}; "
          f"with >= 50: {sum(c >= 50 for c in priv.values())}")
    print("  top 15:", sorted(priv.items(), key=lambda kv: -kv[1])[:15])
    y = pd.to_numeric(df["label"], errors="coerce").fillna(0).to_numpy(dtype=int)
    rule = dominant_src_sets(src, atype, ~normal, 0.05, 8, 0.40, set())
    print("\ndominant-source rule (5%, 8) vs ground truth per type:")
    for t, info in rule.items():
        m = (~normal) & (atype == t)
        truth = Counter(src[m & (y == 1)])
        A = set(info["attackers"]); G = set(truth)
        yr = (np.isin(src, list(A)) | np.isin(dst, list(A))) & m; yt = (y == 1) & m
        tp = (yr & yt).sum(); fp = (yr & ~yt).sum(); fn = (~yr & yt).sum()
        print(f"  {t:12s} rows={m.sum():7d} truth-attack rows={yt.sum():7d} truth sources={len(G):4d} (top {truth.most_common(3)})\n"
              f"               rule attackers={sorted(A)} cum share={info['cum']:.2f} weak={info['weak']}  set P/R={len(A & G) / max(1, len(A)):.2f}/{len(A & G) / max(1, len(G)):.2f}"
              f"  row P/R={tp / max(1, tp + fp):.3f}/{tp / max(1, tp + fn):.3f}")
    dur = pd.to_numeric(df["duration"], errors="coerce").fillna(0)
    print("\nduration (s): quantiles", dur.quantile([0.5, 0.9, 0.99, 1.0]).round(3).to_dict(), " > 120 s:", int((dur > 120).sum()))


if __name__ == "__main__":
    main()
