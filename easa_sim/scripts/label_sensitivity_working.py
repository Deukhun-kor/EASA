#!/usr/bin/env python3
"""Label-rule sensitivity measured on the *working* data (review round 3).

  python scripts/label_sensitivity_working.py --grid results/label_sensitivity.csv --out results/label_sensitivity_working.csv

label_sensitivity.py reports how the attacker sets and the row labels of the raw captures move with the rule's
thresholds.  This script applies the same alternative attacker sets to the rows that the experiments actually use:
the sampled, split working pool (train / val / test) and, within the test split, the records of the replayed attacker
traces (the evaluation campaigns) and the benign device traces (calibration and evaluation segments).  For every grid
setting and attack type it reports how many working rows would change label and, for the evaluated attacker traces,
what share of their records would lose the attack label.  Weak-type exclusion is reported as a flag, not as relabelled
rows, because an excluded type is absent from the pool rather than relabelled.

Like label_sensitivity.py this is a rule-sensitivity audit, not a ground-truth audit.
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
    ap.add_argument("--grid", default="results/label_sensitivity.csv")
    ap.add_argument("--out", default="results/label_sensitivity_working.csv")
    a = ap.parse_args()
    cfg = load_config(a.config)
    pool = load_pool(cfg, np.random.default_rng(0))
    m = pool.rules_meta["replay_meta"]
    src, dst, attack, y = np.asarray(m["src"]), np.asarray(m["dst"]), np.asarray(m["attack"]), pool.y
    fam = pool.family
    split = np.full(len(y), "", dtype=object)
    split[pool.train_idx] = "train"; split[pool.val_idx] = "val"; split[pool.test_idx] = "test"
    bank = ReplayBank(pool, cfg)
    # rows of the replayed attacker traces (evaluation campaigns) and of the benign device traces
    trace_rows = {f: np.concatenate([t.rows for t in ts]) for f, ts in bank.attack.items()}
    benign_eval = np.concatenate([t.rows for t in bank.benign.values()])
    benign_cal = np.concatenate([t.rows for t in bank.benign_cal.values()])
    grid = pd.read_csv(a.grid)
    out = []
    for (ms, ma, wk), g in grid.groupby(["min_share", "max_attackers", "weak_threshold"]):
        for _, r in g.iterrows():
            t = r["attack"]
            rows = np.flatnonzero(attack == t)
            if len(rows) == 0:   # type not in the working pool (excluded as weak by the default rule)
                out.append({"min_share": ms, "max_attackers": ma, "weak_threshold": wk, "attack": t, "in_pool": False,
                            "alt_weak": bool(r["alt_weak"]), "default_weak": bool(r["default_weak"])})
                continue
            B = set(str(r["alt_attackers"]).split()) if isinstance(r["alt_attackers"], str) else set()
            lab_b = np.isin(src[rows], list(B)) | np.isin(dst[rows], list(B))
            lab_a = y[rows] == 1
            changed = lab_a != lab_b
            att_rows = rows[y[rows] == 1]           # family of the type = family of its attack-labelled rows (background rows are BENIGN)
            family = str(fam[att_rows][0]) if len(att_rows) else str(fam[rows][0])
            rec = {"min_share": ms, "max_attackers": ma, "weak_threshold": wk, "attack": t, "in_pool": True,
                   "family": family, "default_weak": bool(r["default_weak"]), "alt_weak": bool(r["alt_weak"]),
                   "working_rows": len(rows), "changed_frac_all": float(changed.mean()),
                   "attack_to_benign_frac": float((lab_a & ~lab_b).sum() / max(1, lab_a.sum())),
                   "benign_to_attack_frac": float((~lab_a & lab_b).sum() / max(1, (~lab_a).sum()))}
            for s in ("train", "val", "test"):
                ms_ = split[rows] == s
                rec[f"changed_frac_{s}"] = float(changed[ms_].mean()) if ms_.any() else np.nan
                rec[f"rows_{s}"] = int(ms_.sum())
            # evaluated attacker traces of this type's family (test split, designated attackers)
            f = rec["family"]; tr = trace_rows.get(f, np.empty(0, dtype=int))
            tr = tr[np.isin(tr, rows)]
            if len(tr):
                lb = np.isin(src[tr], list(B)) | np.isin(dst[tr], list(B))
                rec["trace_rows"] = int(len(tr)); rec["trace_rows_losing_attack_label_frac"] = float((~lb).mean())
            else:
                rec["trace_rows"] = 0; rec["trace_rows_losing_attack_label_frac"] = np.nan
            out.append(rec)
    # benign device traces: rows of the benign chain are never relabelled by the rule (they carry no attacker address),
    # but background rows of attack captures can be; report how many calibration / evaluation benign rows are affected
    df = pd.DataFrame(out)
    bg = np.flatnonzero((fam != BENIGN) & (y == 0))
    print(f"benign device traces: calibration {len(benign_cal):,} rows, evaluation {len(benign_eval):,} rows "
          f"(all from the Benign chain: {int(np.isin(benign_cal, bg).sum()) + int(np.isin(benign_eval, bg).sum())} background rows of attack captures)")
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    df.to_csv(a.out, index=False)
    pd.set_option("display.width", 220)
    d = df[df["in_pool"] == True]
    summ = d.groupby(["min_share", "max_attackers"]).apply(
        lambda g: pd.Series({"changed_all_wt": np.average(g["changed_frac_all"], weights=g["working_rows"]),
                             "changed_test_wt": np.average(g["changed_frac_test"].fillna(0), weights=g["rows_test"]),
                             "trace_losing_wt": np.average(g["trace_rows_losing_attack_label_frac"].fillna(0), weights=g["trace_rows"].clip(lower=1)),
                             "max_changed_type": g["changed_frac_all"].max()}))
    print(summ.round(4).to_string())
    print("saved ->", a.out)


if __name__ == "__main__":
    main()
