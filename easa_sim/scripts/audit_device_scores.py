#!/usr/bin/env python3
"""Per-device detector view of the benign traces, aggregated over seeds (revision round 1).

  python scripts/audit_device_scores.py results/traces/r1_recovery --config EASA_full --out results/r1_device_scores.csv

For every replayed device, over the epochs in which it is NOT under a campaign, reports the mean and 10th percentile
of the network score S_net = 1 - f_theta(window), the share of epochs at level >= 2 and >= 3, and (if config/default.yaml
and the data are available) whether the device's address is a designated attacker of some attack type. One row per
device (mean over seeds), sorted by mean S_net: the devices at the top are those whose *benign* traffic the detector
scores as attack-like under every seed.
"""
import argparse
import glob
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("traces_dir"); ap.add_argument("--config", default="EASA_full"); ap.add_argument("--out", default="results/r1_device_scores.csv")
    ap.add_argument("--map", action="store_true", help="load the pool to map device ids to IP addresses / attacker status (2 min)")
    a = ap.parse_args()
    files = sorted(glob.glob(os.path.join(a.traces_dir, f"{a.config}_seed*.parquet")) + glob.glob(os.path.join(a.traces_dir, f"{a.config}_seed*.csv.gz")))
    rows = []
    for f in files:
        seed = int(os.path.basename(f).split("_seed")[1].split(".")[0])
        df = pd.read_parquet(f) if f.endswith(".parquet") else pd.read_csv(f)
        clean = df[~df["attacking"].astype(bool)]
        g = clean.groupby("device")
        r = pd.DataFrame({"S_net_mean": g["S_net"].mean(), "S_net_p10": g["S_net"].quantile(0.1), "share_L2plus": g["level"].apply(lambda s: float((s >= 2).mean())),
                          "share_L3": g["level"].apply(lambda s: float((s >= 3).mean())), "n_flows_per_epoch": g["n_flows"].mean(),
                          "dclass": g["dclass"].first()})
        r["seed"] = seed; rows.append(r.reset_index())
    d = pd.concat(rows, ignore_index=True)
    agg = d.groupby("device").agg(seeds=("seed", "count"), S_net_mean=("S_net_mean", "mean"), S_net_p10=("S_net_p10", "mean"),
                                  share_L2plus=("share_L2plus", "mean"), share_L3=("share_L3", "mean"), flows_per_epoch=("n_flows_per_epoch", "mean"))
    if a.map:
        from easa.config import load_config
        from easa.data import load_pool
        from easa.replay import ReplayBank
        cfg = load_config("config/default.yaml"); pool = load_pool(cfg, np.random.default_rng(0)); rb = ReplayBank(pool, cfg)
        ids = rb.devices_with_benign; n_gw = cfg["topology"]["n_gateways"]
        att = {ip: sorted(t for t, v in pool.rules_meta["replay_meta"]["attacker_sets"].items() if ip in v["attackers"])
               for v_ in pool.rules_meta["replay_meta"]["attacker_sets"].values() for ip in v_["attackers"]}
        m = {f"g{g}-d{i:03d}": rb.device_ips[k] for g in range(n_gw) for i, k in enumerate(ids[g::n_gw])}
        agg["ip"] = agg.index.map(m.get); agg["attacker_of"] = agg["ip"].map(lambda ip: ";".join(att.get(ip, [])))
    agg = agg.sort_values("S_net_mean")
    agg.to_csv(a.out)
    pd.set_option("display.width", 220)
    print(agg.round(3).head(15).to_string())
    print(f"\n{len(agg)} devices; saved -> {a.out}")


if __name__ == "__main__":
    main()
