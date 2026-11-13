#!/usr/bin/env python3
"""Identity of in-subnet source addresses in the IoT-DIAD 2024 *packet-based* feature release (revision round 1).

The flow release carries no device identity across captures (DHCP). The packet-based release
("Device Identification_Anomaly Detection - Packet Based Features") carries, per packet, `src_ip`,
`src_mac` (replaced by the device name for the testbed's catalogued devices) and `eth_src_oui`.
This script counts, over the first --max-mb megabytes of each given packet CSV, the triples
(src_ip, src_mac, eth_src_oui) for packets whose source is in 192.168.137.0/24, and prints the
identities of the addresses of interest. results/v4/iotdiad_packet_identity.json was produced
this way (first file of each attack type, first 100 MB, read through the dataset portal).

  python scripts/packet_identity_check.py --max-mb 100 --addresses 23,41,66,128,133,173,207 \
      "data/IoT-DIAD-2024/packet/BenignTraffic/BenignTraffic.csv" "data/IoT-DIAD-2024/packet/Web-Based/SqlInjection/SqlInjection.csv" ...
"""
import argparse
import collections
import json
import os


def scan(path: str, max_mb: float | None):
    counts = collections.Counter(); lan = 0; nbytes = 0; limit = None if max_mb is None else int(max_mb * 1e6)
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        hdr = fh.readline(); nbytes += len(hdr)
        cols = [c.strip() for c in hdr.split(",")]
        i_mac, i_ip, i_oui = cols.index("src_mac"), cols.index("src_ip"), cols.index("eth_src_oui")
        nf = max(i_mac, i_ip, i_oui) + 1
        for line in fh:
            nbytes += len(line)
            f = line.split(",", nf)
            if len(f) <= i_oui:
                continue
            ip = f[i_ip]
            if ip.startswith("192.168.137."):
                counts[(ip, f[i_mac], f[i_oui].strip('"'))] += 1; lan += 1
            if limit is not None and nbytes >= limit:
                break
    return counts, lan, nbytes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--max-mb", type=float, default=100.0, help="bytes read per file (None = whole file)")
    ap.add_argument("--addresses", default="23,41,66,128,133,173,207", help="last octets of interest")
    ap.add_argument("--out", default=None, help="JSON output")
    a = ap.parse_args()
    want = {"192.168.137." + x.strip() for x in a.addresses.split(",") if x.strip()}
    out = {"_method": "first --max-mb MB of each file; (src_ip, src_mac, eth_src_oui) counted for in-subnet sources", "files": {}}
    for p in a.files:
        counts, lan, nbytes = scan(p, a.max_mb)
        by_ip = collections.defaultdict(list)
        for (ip, mac, oui), n in counts.items():
            by_ip[ip].append({"src_mac": mac, "oui": oui, "packets": n})
        for ip in by_ip:
            by_ip[ip].sort(key=lambda d: -d["packets"])
        out["files"][p] = {"bytes_read": nbytes, "lan_source_packets": lan, "sources": dict(sorted(by_ip.items(), key=lambda kv: int(kv[0].split(".")[3])))}
        print(f"{os.path.basename(p)}  {nbytes/1e6:.0f} MB  LAN-source packets {lan}")
        for ip in sorted(want, key=lambda s: int(s.split(".")[3])):
            if ip in by_ip:
                print("   ", ip, [(d["src_mac"], d["oui"], d["packets"]) for d in by_ip[ip]])
    if a.out:
        with open(a.out, "w") as f:
            json.dump(out, f, indent=1)
        print("saved ->", a.out)


if __name__ == "__main__":
    main()
