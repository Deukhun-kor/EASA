#!/usr/bin/env python3
r"""Inspect the downloaded IoT-DIAD 2024 flow CSVs and print the facts needed to configure replay
and row-level labelling.

  python scripts\inspect_iotdiad.py --nrows 300000 > results\inspect_300k.txt 2>&1
  python scripts\inspect_iotdiad.py > results\inspect_full.txt 2>&1        # full scan (~10 min)

Sections:
  A. non-standard / headerless files
  B. per-file table (rows, time span, #src, #dst)
  C. device universe (benign in-subnet Src IPs)
  D. per attack type: top Src and Dst IPs by flow count -> identifies attacker machines & victims
  E. attacker candidates: in-subnet IPs that are sources in attack captures but never in benign
"""
import argparse
import glob
import ipaddress
import os
import sys
from collections import Counter, defaultdict

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from easa.data.iotdiad import FAMILY_DIR, REQUIRED, _parse_ts, is_headerless, normalise_columns, read_csv_canon, read_header  # noqa: E402

SUBNET = ipaddress.ip_network("192.168.137.0/24")
EXCLUDE = {"192.168.137.1"}


def in_subnet(ip):
    try: return ipaddress.ip_address(ip) in SUBNET
    except ValueError: return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.join("data", "IoT-DIAD-2024", "flow"))
    ap.add_argument("--nrows", type=int, default=None)
    ap.add_argument("--top", type=int, default=6)
    a = ap.parse_args()
    files = sorted(glob.glob(os.path.join(a.root, "**", "*.csv"), recursive=True))
    print(f"files: {len(files)}   total size: {sum(os.path.getsize(f) for f in files)/1e9:.2f} GB\n")

    rows, odd = [], []
    benign_src = Counter()
    src_by_attack, dst_by_attack = defaultdict(Counter), defaultdict(Counter)
    for f in files:
        rel = os.path.relpath(f, a.root).split(os.sep)
        fam = FAMILY_DIR.get(rel[0], rel[0]); attack = rel[1] if len(rel) > 2 else fam
        hl = is_headerless(f)
        hdr = read_header(f); cmap = normalise_columns(hdr)
        missing = [r for r in REQUIRED if r not in cmap.values()]
        if missing:
            odd.append((f, missing, hdr[:8])); continue
        df = read_csv_canon(f, usecols=["Src IP", "Dst IP", "Timestamp"], nrows=a.nrows)
        ts = _parse_ts(df["Timestamp"])
        dur = (ts.max() - ts.min()).total_seconds() if ts.notna().any() else float("nan")
        src = df["Src IP"].astype(str); dst = df["Dst IP"].astype(str)
        if fam == "Benign":
            benign_src.update(src)
        src_by_attack[(fam, attack)].update(src); dst_by_attack[(fam, attack)].update(dst)
        rows.append((fam, attack, os.path.basename(f) + (" [headerless]" if hl else ""), len(df), ts.min(), ts.max(), dur,
                     src.nunique(), dst.nunique(), round(float(ts.isna().mean()), 4)))

    print("A. non-standard files")
    if odd:
        for f, missing, head in odd: print(f"  {f}\n     missing={missing} first cols={head}")
    else:
        print("  none (headerless files were auto-detected and read with the canonical header)")

    tab = pd.DataFrame(rows, columns=["family", "attack", "file", "rows", "t_start", "t_end", "dur_s", "n_src", "n_dst", "ts_nan"])
    pd.set_option("display.width", 230); pd.set_option("display.max_rows", 300); pd.set_option("display.max_colwidth", 45)
    print("\nB. per-file table"); print(tab.to_string(index=False))
    print("\nrows per family:\n" + tab.groupby("family")["rows"].sum().to_string())

    devices = sorted((ip for ip in benign_src if in_subnet(ip) and ip not in EXCLUDE),
                     key=lambda s: tuple(int(p) for p in s.split(".")))
    dev_set = set(devices)
    print(f"\nC. device universe: {len(devices)} in-subnet Src IPs in Benign (excluding {sorted(EXCLUDE)})")
    print("  ", devices)
    other = sorted(ip for ip in benign_src if not in_subnet(ip) and ipaddress.ip_address(ip).is_private) if benign_src else []
    print("   other private src in benign (ignored):", other[:10])

    print(f"\nD. per attack type: top-{a.top} Src / Dst IPs by flow count   [dev]=device  [SUB]=in-subnet non-device  [pub]=public")
    def tag(ip):
        return "dev" if ip in dev_set else ("SUB" if in_subnet(ip) else "pub")
    for key in sorted(src_by_attack):
        if key[0] == "Benign": continue
        s, dd = src_by_attack[key], dst_by_attack[key]; tot = sum(s.values())
        print(f"  {key[0]:10s} {key[1][:28]:28s} flows={tot:,}")
        print("     src: " + "  ".join(f"{ip}[{tag(ip)}]={n/tot:.0%}" for ip, n in s.most_common(a.top)))
        print("     dst: " + "  ".join(f"{ip}[{tag(ip)}]={n/tot:.0%}" for ip, n in dd.most_common(a.top)))

    print("\nE. attacker candidates: in-subnet Src IPs in attack captures that NEVER appear as Src in Benign")
    cand = Counter()
    for key, s in src_by_attack.items():
        if key[0] == "Benign": continue
        for ip, n in s.items():
            if in_subnet(ip) and ip not in benign_src and ip not in EXCLUDE: cand[ip] += n
    for ip, n in cand.most_common(30):
        where = [k[1] for k, s in src_by_attack.items() if k[0] != "Benign" and ip in s]
        print(f"   {ip:16s} flows={n:>9,}  seen in: {sorted(set(where))[:6]}")
    if not cand: print("   (none)")


if __name__ == "__main__":
    main()
