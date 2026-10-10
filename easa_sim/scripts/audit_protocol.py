#!/usr/bin/env python3
"""Implementation audit of the protocol-v3 replay invariants (review round 3).

  python scripts/audit_protocol.py --config config/default.yaml > results/log_audit_protocol.txt

Checks, on the working pool actually used by the experiments:
  1. Flow Duration: unit (microseconds in CICFlowMeter), min / max, NaN, negative and > 120 s rows, by split.
     A record longer than 120 s is made available at start + 120 s, i.e. before its real end; the count says
     whether that case occurs.
  2. Availability ordering: every replay trace is sorted by availability time (start + duration); the audit counts
     the records whose availability order differs from their start order (the records that the v3 rule actually moves).
  3. Calibration / evaluation boundary: per device, record counts of the two segments, the last availability time of
     the calibration segment vs the first of the evaluation segment (must not overlap), and the number of evaluation
     records whose *start* precedes the end of the calibration segment (flows that straddle the boundary; they are
     assigned to the segment in which they become available).
  4. Wrap: replay-trace durations vs the 3,600 s run (how many device traces wrap within a run and how often), and
     the monotonicity of the virtual clock of every trace.
  5. Evaluation sample: unique records per segment, attack-trace records per family and designated attacker, and the
     absolute time range of the test split.
"""
import argparse
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from easa.config import load_config  # noqa: E402
from easa.data import load_pool  # noqa: E402
from easa.data.pool import BENIGN  # noqa: E402
from easa.replay import ReplayBank  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/default.yaml")
    ap.add_argument("--run_s", type=float, default=3600.0)
    a = ap.parse_args()
    cfg = load_config(a.config)
    pool = load_pool(cfg, np.random.default_rng(0))
    m = pool.rules_meta["replay_meta"]
    abs_t = np.asarray(m["abs_t"], float); dur = np.asarray(m["dur_s"], float)
    split = np.full(len(pool.y), "none", dtype=object)
    split[pool.train_idx] = "train"; split[pool.val_idx] = "val"; split[pool.test_idx] = "test"
    print("== 1. Flow Duration (seconds after /1e6; raw column is microseconds in CICFlowMeter; clipped to [0,120] in the pool)")
    raw = np.asarray(m.get("dur_raw_s", dur), float)
    print(f"   raw duration: min={raw.min():.3f} s, max={raw.max():.3f} s, NaN/negative mapped to 0 at load; rows == 120 s: {(raw == 120.0).sum():,}; "
          f"rows > 120 s: {(raw > 120.0).sum():,} (max {raw.max():.1f} s); rows == 0 s: {(raw == 0).sum():,}")
    print(f"   pool stores dur_s clipped: min={dur.min():.3f} max={dur.max():.3f} mean={dur.mean():.3f} median={np.median(dur):.3f}")
    for s in ("train", "val", "test"):
        ms = split == s
        print(f"   {s}: n={ms.sum():,} raw==120: {(raw[ms] == 120).sum():,} raw>120: {(raw[ms] > 120).sum():,} raw==0: {(raw[ms] == 0).sum():,}")
    over = np.flatnonzero(raw > 120.0); at = np.flatnonzero(raw == 120.0)
    bank = ReplayBank(pool, cfg)
    avail = bank.abs_t
    # are the capped rows used by any replay trace (calibration / evaluation benign, attacker traces)?
    used = {"calibration": np.concatenate([t.rows for t in bank.benign_cal.values()]),
            "evaluation": np.concatenate([t.rows for t in bank.benign.values()]),
            "attacker": np.concatenate([t.rows for ts in bank.attack.values() for t in ts])}
    for lab, idx in (("raw > 120 s", over), ("raw == 120 s", at)):
        hit = {k: int(np.isin(idx, v).sum()) for k, v in used.items()}
        print(f"   rows with {lab} that occur in replay traces: " + ", ".join(f"{k} {n}" for k, n in hit.items()))
        if len(idx):
            fam_ = pool.family[idx]; print(f"      by family: {dict(zip(*np.unique(fam_, return_counts=True)))}; by attack-label: attack {int((pool.y[idx]==1).sum())}, benign {int((pool.y[idx]==0).sum())}")
    print(f"\n== 2. Availability ordering (availability={bank.availability})")
    moved = 0; total = 0
    for f, ts in bank.attack.items():
        for t in ts:
            r = t.rows; total += len(r)
            start_order = np.argsort(abs_t[r], kind="stable"); avail_order = np.argsort(avail[r], kind="stable")
            moved += int((start_order != avail_order).sum())
            assert np.all(np.diff(avail[r]) >= 0), "trace not sorted by availability"
    for t in list(bank.benign.values()) + list(bank.benign_cal.values()):
        r = t.rows; total += len(r)
        moved += int((np.argsort(abs_t[r], kind="stable") != np.argsort(avail[r], kind="stable")).sum())
        assert np.all(np.diff(avail[r]) >= 0), "trace not sorted by availability"
    print(f"   all traces sorted by availability time: OK; records whose position differs from start order: {moved:,} of {total:,} ({100*moved/max(1,total):.2f}%)")
    print(f"\n== 3. Calibration / evaluation boundary (calibration_fraction={bank.cal_fraction:.4f}; segments split by record count in availability order)")
    overlap = 0; straddle = 0; n_dev = 0; cal_rows = 0; eval_rows = 0; shared = 0
    for i, te in bank.benign.items():
        tc = bank.benign_cal[i]
        if tc is te: continue
        n_dev += 1; cal_rows += len(tc.rows); eval_rows += len(te.rows)
        shared += len(np.intersect1d(tc.rows, te.rows))
        last_cal = avail[tc.rows].max(); first_eval = avail[te.rows].min()
        overlap += int(first_eval < last_cal)
        straddle += int((abs_t[te.rows] < last_cal).sum())   # evaluation records that *started* before the calibration segment ended
    print(f"   devices with both segments: {n_dev}; calibration rows {cal_rows:,}, evaluation rows {eval_rows:,}, shared rows {shared}")
    print(f"   devices whose evaluation segment becomes available before the calibration segment ends: {overlap}")
    print(f"   evaluation records that started before the end of the calibration segment (straddling flows, assigned by availability): {straddle:,}")
    print(f"\n== 4. Wrap (run length {a.run_s:.0f} s)")
    de = np.array([t.duration for t in bank.benign.values()]); dc = np.array([t.duration for t in bank.benign_cal.values()])
    print(f"   evaluation trace duration (s): median {np.median(de):.0f}, min {de.min():.0f}, max {de.max():.0f}; traces shorter than one run: {(de < a.run_s).sum()} of {len(de)}"
          f" (mean wraps per run {np.mean(np.maximum(0, a.run_s / de - 1)):.2f})")
    print(f"   calibration trace duration (s): median {np.median(dc):.0f}, min {dc.min():.0f}; shorter than the 1,800 s pass: {(dc < 1800).sum()} of {len(dc)}")
    for f, ts in bank.attack.items():
        d = np.array([t.duration for t in ts])
        print(f"   attack {f}: {len(ts)} traces, duration median {np.median(d):.0f} s (min {d.min():.0f}); traces shorter than the longest campaign (600 s): {(d < 600).sum()}")
    mono = all(np.all(np.diff(t.t) >= 0) for ts in bank.attack.values() for t in ts) and all(np.all(np.diff(t.t) >= 0) for t in bank.benign.values())
    print(f"   virtual clock monotone within every trace: {mono}")
    print("\n== 5. Evaluation sample")
    te = pool.test_idx
    ts_ = pd.to_datetime(abs_t[te], unit="s")
    print(f"   test split: {len(te):,} rows, time range {ts_.min()} .. {ts_.max()}")
    for f, ts in bank.attack.items():
        print(f"   {f}: {len(ts)} designated-attacker traces, records {[len(t.rows) for t in ts]}")
    print(f"   benign device traces: {len(bank.benign)} devices; calibration records {sum(len(t.rows) for t in bank.benign_cal.values()):,}; "
          f"evaluation records {sum(len(t.rows) for t in bank.benign.values()):,}")
    print("   records are CICFlowMeter flow records as released (no further flow-ID aggregation)")


if __name__ == "__main__":
    main()
