#!/usr/bin/env python3
"""Manifest of the label-hygiene step of protocol v4 (revision r1, A1 of the internal review).

  python scripts/audit_hygiene.py --config config/v4.yaml --out results/v4/hygiene_manifest.csv

Loads the IoT-DIAD pool with the attacker hosts KEPT (protocol v3 device universe) and lists, for every Benign-chain
address that the dominant-source rule designates as an attacker of some attack type: the types it is designated for
(with its flow share there), its Benign-chain rows in the working set as source and as destination, how those rows
fall into the train / validation / test splits, and whether the address was a replayed device (a benign trace in the
test split). The totals are the rows that `iotdiad_attacker_hosts: drop` removes.
"""
import argparse
import copy
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from easa.config import load_config  # noqa: E402
from easa.data import load_pool  # noqa: E402
from easa.replay import ReplayBank  # noqa: E402


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--config", default="config/v4.yaml"); ap.add_argument("--out", default="results/v4/hygiene_manifest.csv")
    a = ap.parse_args()
    cfg = load_config(a.config)
    cfg = copy.deepcopy(cfg); cfg["data"]["iotdiad_attacker_hosts"] = "keep"
    pool = load_pool(cfg, np.random.default_rng(0)); rb = ReplayBank(pool, cfg)
    m = pool.rules_meta["replay_meta"]
    src, dst, fam, device = np.asarray(m["src"]), np.asarray(m["dst"]), pool.family, np.asarray(m["device"])
    chain = device >= 0                                   # Benign-chain rows (device id valid there only)
    att = m["attacker_sets"]
    hosts = sorted({ip for v in att.values() for ip in v["attackers"]} & set(m["device_ips"]), key=lambda s: tuple(int(p) for p in s.split(".")))
    split = np.full(len(src), "", dtype=object); split[pool.train_idx] = "train"; split[pool.val_idx] = "val"; split[pool.test_idx] = "test"
    replayed = {rb.device_ips[k] for k in rb.devices_with_benign}
    rows = []
    for ip in hosts:
        s_ = chain & (src == ip); d_ = chain & (dst == ip); any_ = s_ | d_
        rows.append({"ip": ip, "designated_for": "; ".join(f"{t} ({v['shares'].get(ip, float('nan')):.2f})" for t, v in att.items() if ip in v["attackers"]),
                     "n_types": sum(ip in v["attackers"] for v in att.values()),
                     "benign_chain_rows_as_src": int(s_.sum()), "benign_chain_rows_as_dst": int(d_.sum()), "benign_chain_rows_any": int(any_.sum()),
                     "rows_train": int((any_ & (split == "train")).sum()), "rows_val": int((any_ & (split == "val")).sum()), "rows_test": int((any_ & (split == "test")).sum()),
                     "replayed_device_v3": ip in replayed,
                     "eval_records_v3": len(rb.benign[rb.device_ips.index(ip)].rows) if ip in replayed else 0})
    df = pd.DataFrame(rows)
    allhost = chain & (np.isin(src, hosts) | np.isin(dst, hosts))
    tot = {"ip": "TOTAL (rows removed by drop; a row with two attacker hosts counted once)", "benign_chain_rows_any": int(allhost.sum()),
           "rows_train": int((allhost & (split == "train")).sum()), "rows_val": int((allhost & (split == "val")).sum()), "rows_test": int((allhost & (split == "test")).sum())}
    df = pd.concat([df, pd.DataFrame([tot])], ignore_index=True)
    df.to_csv(a.out, index=False)
    pd.set_option("display.width", 250); print(df.to_string(index=False))
    print(f"\nBenign-chain rows in the working set: {int(chain.sum()):,}; benign rows incl. attack-capture background: {int((fam == 'Benign').sum()):,}; "
          f"removed share of chain rows {100 * allhost.sum() / max(1, chain.sum()):.1f}%, of all benign rows {100 * allhost.sum() / max(1, (fam == 'Benign').sum()):.1f}%")
    print("saved ->", a.out)


if __name__ == "__main__":
    main()
