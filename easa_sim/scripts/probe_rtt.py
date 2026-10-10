#!/usr/bin/env python3
"""Measure baseline RTT to the deployed cloud service (reported in the paper's
setup section, separately from in-simulation RTTs).

  EASA_API_KEY=... python scripts/probe_rtt.py https://easa-cloud-xxxx-asia-northeast3.run.app --n 200
"""
import argparse
import os
import time

import numpy as np
import requests


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base_url"); ap.add_argument("--n", type=int, default=200); ap.add_argument("--out", default="results/rtt_probe.csv")
    a = ap.parse_args()
    s = requests.Session(); s.headers["X-API-Key"] = os.environ.get("EASA_API_KEY", "")
    rows = []
    for path in ["/health", "/sync/model", "/sync/revocations"]:
        lat = []
        for _ in range(a.n):
            t0 = time.perf_counter(); r = s.get(a.base_url.rstrip("/") + path, timeout=10); r.raise_for_status()
            lat.append((time.perf_counter() - t0) * 1000)
            time.sleep(0.05)
        arr = np.array(lat)
        rows.append((path, arr.mean(), np.percentile(arr, 50), np.percentile(arr, 95), arr.max(), arr.std()))
        print(f"{path:20s} mean={arr.mean():7.1f} p50={np.percentile(arr,50):7.1f} p95={np.percentile(arr,95):7.1f} "
              f"max={arr.max():7.1f} ms (n={a.n})")
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f:
        f.write("path,mean_ms,p50_ms,p95_ms,max_ms,std_ms\n")
        for r in rows: f.write(",".join(str(x) for x in r) + "\n")
    print("saved", a.out)


if __name__ == "__main__":
    main()
