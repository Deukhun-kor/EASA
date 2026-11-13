#!/usr/bin/env python3
"""List the replayed devices of a protocol: gateway id, IP, calibration / evaluation records and trace durations,
and whether the address is a designated attacker (revision round 1).

  python scripts/list_devices.py --config config/v4.yaml [--out results/v4/devices_v4.csv]
"""
import argparse
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from easa.config import load_config  # noqa: E402
from easa.data import load_pool  # noqa: E402
from easa.replay import ReplayBank  # noqa: E402


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--config", default="config/default.yaml"); ap.add_argument("--out", default=None)
    a = ap.parse_args()
    cfg = load_config(a.config); pool = load_pool(cfg, np.random.default_rng(0)); rb = ReplayBank(pool, cfg)
    ids = rb.devices_with_benign; n_gw = cfg["topology"]["n_gateways"]
    att = {ip for v in pool.rules_meta["replay_meta"]["attacker_sets"].values() for ip in v["attackers"]}
    rows = []
    for g in range(n_gw):
        for i, k in enumerate(ids[g::n_gw]):
            ev, ca = rb.benign[k], rb.benign_cal[k]
            rows.append({"device": f"g{g}-d{i:03d}", "ip": rb.device_ips[k], "attacker_host": rb.device_ips[k] in att,
                         "eval_records": len(ev.rows), "eval_duration_s": round(ev.duration, 1), "wraps_per_hour": round(3600 / max(ev.duration, 1e-9), 1),
                         "cal_records": len(ca.rows), "cal_duration_s": round(ca.duration, 1)})
    df = pd.DataFrame(rows).sort_values("eval_duration_s")
    pd.set_option("display.width", 200); print(df.to_string(index=False))
    if a.out:
        df.to_csv(a.out, index=False); print("saved ->", a.out)


if __name__ == "__main__":
    main()
