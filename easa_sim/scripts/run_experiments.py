#!/usr/bin/env python3
"""Run the Table-3 grid.

Examples
  # smoke test on synthetic data, 2 seeds, local cloud mock
  python scripts/run_experiments.py --set data.source=synthetic --set cloud.mode=local --seeds 2 --configs EASA_full B3_net_only

  # full protocol against the real Seoul deployment
  EASA_API_KEY=... python scripts/run_experiments.py --set cloud.base_url=https://easa-xxxx-asia-northeast3.run.app

  # cloud-outage experiment
  python scripts/run_experiments.py --configs EASA_full --set cloud.outage.enabled=true --out results/outage.csv
"""
import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from easa.config import apply_dotted, load_config  # noqa: E402
from easa.data import load_pool  # noqa: E402
from easa.runner import run_grid  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/default.yaml")
    ap.add_argument("--configs", nargs="*", default=None, help="subset of Table-3 configurations")
    ap.add_argument("--seeds", type=int, default=None, help="override experiment.seeds")
    ap.add_argument("--set", action="append", default=[], help="dotted override, e.g. cloud.mode=local")
    ap.add_argument("--out", default=None)
    ap.add_argument("--fresh", action="store_true", help="ignore an existing --out file instead of resuming it")
    args = ap.parse_args()

    cfg = apply_dotted(load_config(args.config), args.set)
    n_seeds = args.seeds or cfg["experiment"]["seeds"]
    names = args.configs or list(cfg["configs"])
    os.makedirs(cfg["experiment"]["out_dir"], exist_ok=True)
    out_csv = args.out or os.path.join(cfg["experiment"]["out_dir"], f"{cfg['experiment']['name']}.csv")
    logging.basicConfig(level=getattr(logging, cfg["experiment"].get("log_level", "INFO")),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    # load the pool once (data split is seed-0 fixed so every configuration sees identical traces)
    pool = load_pool(cfg, np.random.default_rng(0))
    df = run_grid(cfg, names, list(range(n_seeds)), out_csv, pool=pool, resume=not args.fresh)
    print(df.groupby("config")[["f1_L2", "false_quarantine_rate", "ttc_mean_s", "reauth_per_device_hour",
                                "cross_site_recall_L2"]].agg(["mean", "std"]).round(4).to_string())
    print(f"\nsaved -> {out_csv}")


if __name__ == "__main__":
    main()
