#!/usr/bin/env python3
"""Sensitivity analysis (Appendix): one axis at a time around the frozen protocol-v2 defaults.

  python scripts/sweep.py --seeds 10 --out results/sensitivity.csv            # all axes, local cloud mock
  python scripts/sweep.py --axes w_net k --seeds 10 --out results/sens_wk.csv  # a subset

Axes (default values in brackets):
  w_net      trust.w_net in {0.4,0.5,[0.6],0.7,0.8}   (w_pos/w_hist rescaled to keep the sum = 1, same 0.25:0.15 ratio)
  beta       trust.beta in {0.5,[0.7],0.9}
  h          policy.h_epochs in {3,[5],10}
  k          trust.window_topk in {1,[3],5}
  target_fpr policy.calibrate.target_fpr in {0.01,[0.02],0.05}

Each point runs EASA_full and B3_net_only for --seeds seeds on the in-process cloud mock
(transport=local; the real service adds nothing to a parameter sweep).  Output rows carry
`axis` and `value` so scripts/make_figures.py --sens can plot them.  Resumable like run_experiments.
"""
import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from easa.config import apply_dotted, load_config  # noqa: E402
from easa.data import load_pool  # noqa: E402
from easa.runner import run_grid  # noqa: E402

AXES = {
    "w_net":      ("trust.w_net", [0.4, 0.5, 0.6, 0.7, 0.8]),
    "beta":       ("trust.beta", [0.5, 0.7, 0.9]),
    "h":          ("policy.h_epochs", [3, 5, 10]),
    "k":          ("trust.window_topk", [1, 3, 5]),
    "target_fpr": ("policy.calibrate.target_fpr", [0.01, 0.02, 0.05]),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/default.yaml")
    ap.add_argument("--axes", nargs="*", default=list(AXES))
    ap.add_argument("--configs", nargs="*", default=["EASA_full", "B3_net_only"])
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--set", action="append", default=[])
    ap.add_argument("--out", default="results/sensitivity.csv")
    ap.add_argument("--fresh", action="store_true", help="discard --out and the _sweep_tmp cache before running (required after a protocol change)")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    base = apply_dotted(load_config(a.config), ["cloud.transport=local"] + a.set)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    pool = load_pool(base, np.random.default_rng(0))

    import shutil
    if a.fresh:
        if os.path.exists(a.out): os.remove(a.out)
        shutil.rmtree(os.path.join(os.path.dirname(a.out) or ".", "_sweep_tmp"), ignore_errors=True)
    done = set()
    if os.path.exists(a.out):
        prev = pd.read_csv(a.out)
        done = set(zip(prev["axis"], prev["value"].astype(str), prev["config"], prev["seed"]))
        logging.info("resuming %s: %d rows", a.out, len(prev))
        if "calibration_fraction" not in prev.columns:
            raise SystemExit(f"{a.out} was produced by an older protocol (no calibration_fraction column); rerun with --fresh")
    tmp_dir = os.path.join(os.path.dirname(a.out) or ".", "_sweep_tmp"); os.makedirs(tmp_dir, exist_ok=True)

    for axis in a.axes:
        key, values = AXES[axis]
        for v in values:
            if all((axis, str(v), c, s) in done for c in a.configs for s in range(a.seeds)):
                continue
            sets = [f"{key}={v}"]
            if axis == "w_net":                       # keep the weights normalised with the default pos:hist ratio
                rest = 1.0 - v; sets += [f"trust.w_pos={rest * 0.625:.4f}", f"trust.w_hist={rest * 0.375:.4f}"]
            cfg = apply_dotted(base, sets)
            cfg["experiment"]["name"] = f"sens_{axis}_{v}"
            tmp_csv = os.path.join(tmp_dir, f"{axis}_{v}.csv")
            logging.info("=== axis=%s value=%s (%s)", axis, v, ", ".join(sets))
            df = run_grid(cfg, a.configs, list(range(a.seeds)), tmp_csv, pool=pool, resume=True)
            df["axis"] = axis; df["value"] = v
            out = pd.concat([pd.read_csv(a.out), df], ignore_index=True) if os.path.exists(a.out) else df
            out = out.drop_duplicates(subset=["axis", "value", "config", "seed"], keep="last")
            out.to_csv(a.out, index=False)
    df = pd.read_csv(a.out)
    print(df.groupby(["axis", "value", "config"])[["f1_L2", "fpr_L2", "cross_site_recall_L2", "containment_rate",
                                                   "reauth_per_device_hour"]].mean().round(3).to_string())
    print(f"\nsaved -> {a.out}")


if __name__ == "__main__":
    main()
