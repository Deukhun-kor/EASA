"""FlowPool: a labelled, scaled bank of per-flow feature vectors grouped by
attack family, from which the emulator draws flows for simulated devices.

Why a pool and not a replayed pcap: the public CIC-IoT-2023 *feature* CSVs
carry no device identity or timestamp, so device/time structure must be
emulated. TON_IoT network records *do* carry src_ip and ts and are used as a
realism check (Scenario B). This is stated explicitly in the paper.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

BENIGN = "Benign"


@dataclass
class FlowPool:
    X: np.ndarray                      # (n, d) float32, scaled
    y: np.ndarray                      # (n,) int, 0 = benign, 1 = attack
    family: np.ndarray                 # (n,) str, BENIGN or attack family
    feature_names: list[str]
    train_idx: np.ndarray
    val_idx: np.ndarray
    test_idx: np.ndarray
    rules_meta: dict = field(default_factory=dict)   # columns used by the rule-based detector (B2)

    # ------------------------------------------------------------------
    def __post_init__(self):
        self._families = sorted(set(np.unique(self.family).tolist()) - {BENIGN})
        self._split_idx = {"train": self.train_idx, "val": self.val_idx, "test": self.test_idx}
        # pre-index rows per (split, family) so sampling during simulation is O(1)
        self._by_fam = {s: {f: idx[self.family[idx] == f] for f in self._families + [BENIGN]}
                        for s, idx in self._split_idx.items()}

    def families(self) -> list[str]:
        return self._families

    def idx_where(self, split: str, fam: str | None = None) -> np.ndarray:
        if fam is None:
            return self._split_idx[split]
        return self._by_fam[split].get(fam, np.empty(0, dtype=int))

    def train_split_for_gateway(self, holdout: list[str], gateway: int | None = None, n_gateways: int = 1,
                                partition: str = "shared", device_owner: dict[int, int] | None = None,
                                global_holdout_devices: set[int] | None = None) -> np.ndarray:
        """Local training rows for a gateway: all benign + attacks NOT in holdout.

        partition (revision round 1, editor point 2 -- generalisation with disjoint gateways):
          shared           every gateway trains on the whole training split minus its held-out family (protocol v3;
                           pairwise Jaccard overlap 0.69-0.84 in IoT-DIAD).
          disjoint         the training split is partitioned so that no two gateways share a row: the rows of each
                           attack capture file are cut into n_gateways *contiguous time blocks* (block g -> gateway g;
                           blocks are different captured segments, not an interleaved shuffle; benign background rows
                           of attack captures follow their file), and the benign rows of a real device go to the
                           gateway that replays that device (device_owner), i.e. a gateway trains on the earlier
                           traffic of its own devices only. Every gateway keeps every family it is not holding out,
                           so the held-out-family bookkeeping is unchanged.
          disjoint_device  as `disjoint`, but the benign rows of a real device go to the *next* gateway
                           ((owner + 1) mod n_gateways): a gateway trains on no row of any device it evaluates, so
                           training devices and evaluated devices are disjoint at every gateway.
        Devices that are replayed nowhere (no evaluation trace) are assigned by device index mod n_gateways.
        """
        tr = self.train_idx
        # federation-wide device holdout (revision r1, editor point 2): the benign rows of the held-out devices are
        # removed from EVERY gateway's training set (and hence from the aggregated model); the devices are still
        # replayed and calibrated, so their evaluation is that of devices unseen at training time.
        if global_holdout_devices:
            m = self.rules_meta.get("replay_meta") or {}
            if m.get("device") is None:
                raise ValueError("global_holdout_devices requires per-row device metadata (IoT-DIAD or TON_IoT loader)")
            dev_all = np.asarray(m["device"])
            tr = tr[~np.isin(dev_all[tr], list(global_holdout_devices))]
        if partition == "shared" or gateway is None or n_gateways <= 1:
            return tr[~np.isin(self.family[tr], holdout)]
        if partition not in ("disjoint", "disjoint_device"):
            raise ValueError(f"unknown training partition {partition!r}")
        # the partition is computed on the full training split (before the held-out family is removed), so that the
        # blocks are identical for every gateway and no row is shared; the holdout filter is applied afterwards.
        # It is cached per (partition, gateway, owner map): the per-file sorting is expensive and train_local is called
        # once per federated round.
        key = (partition, int(gateway), int(n_gateways), tuple(sorted((device_owner or {}).items())), tuple(sorted(global_holdout_devices or ())))
        cache = self.__dict__.setdefault("_partition_cache", {})
        if key not in cache:
            m = self.rules_meta.get("replay_meta") or {}
            if m.get("file") is None or m.get("device") is None or m.get("abs_t") is None:
                raise ValueError("training_partition requires per-row file / device / time metadata (IoT-DIAD or TON_IoT loader)")
            fileid = np.asarray(m["file"]); device = np.asarray(m["device"]); abs_t = np.asarray(m["abs_t"], dtype=np.float64)
            own = np.zeros(len(tr), dtype=bool)
            dev_tr = device[tr]
            real_dev = dev_tr >= 0                                   # benign rows of a real device (Benign chain)
            owner = device_owner or {}
            shift = 1 if partition == "disjoint_device" else 0
            gw_of_dev = np.array([(owner.get(int(d), int(d)) + shift) % n_gateways for d in dev_tr[real_dev]], dtype=int)
            own[np.flatnonzero(real_dev)[gw_of_dev == gateway]] = True
            rest = np.flatnonzero(~real_dev)                        # attack-capture rows (attack + background benign)
            f_rest = fileid[tr[rest]]
            codes, uniq = pd.factorize(f_rest)
            for c in range(len(uniq)):
                sel = rest[codes == c]
                order = sel[np.argsort(abs_t[tr[sel]], kind="stable")]
                own[np.array_split(order, n_gateways)[gateway]] = True
            cache[key] = own
        own = cache[key]
        keep = own & ~np.isin(self.family[tr], holdout)
        return tr[keep]

    def sample(self, rng: np.random.Generator, split: str, fam: str, n: int) -> np.ndarray:
        idx = self.idx_where(split, fam)
        if len(idx) == 0:
            raise ValueError(f"no rows for family={fam} split={split}")
        return rng.choice(idx, size=n, replace=len(idx) < n)

    def summary(self) -> str:
        fams, counts = np.unique(self.family, return_counts=True)
        rows = ", ".join(f"{f}:{c:,}" for f, c in zip(fams, counts))
        return (f"FlowPool n={len(self.y):,} d={self.X.shape[1]} "
                f"train/val/test={len(self.train_idx):,}/{len(self.val_idx):,}/{len(self.test_idx):,} | {rows}")


# ----------------------------------------------------------------------
def make_splits(rng: np.random.Generator, n: int, test_frac: float, val_frac: float,
                strata: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Stratified train/val/test split (by family)."""
    train, val, test = [], [], []
    for s in np.unique(strata):
        idx = np.flatnonzero(strata == s)
        rng.shuffle(idx)
        n_test = int(round(len(idx) * test_frac))
        n_val = int(round(len(idx) * val_frac))
        test.append(idx[:n_test]); val.append(idx[n_test:n_test + n_val]); train.append(idx[n_test + n_val:])
    return (np.concatenate(train), np.concatenate(val), np.concatenate(test))


def dedup_rows(X: np.ndarray, y: np.ndarray, fam: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray, float]:
    """Drop exact duplicate feature rows. Returns the duplicate ratio for reporting."""
    _, first = np.unique(X, axis=0, return_index=True)
    keep = np.sort(first)
    ratio = 1.0 - len(keep) / len(X)
    log.info("dedup: removed %.1f%% exact-duplicate rows (%d -> %d)", 100 * ratio, len(X), len(keep))
    return X[keep], y[keep], fam[keep], ratio


def scale_fit_transform(X: np.ndarray, train_idx: np.ndarray, method: str = "log_standard") -> np.ndarray:
    """Fit on train rows only. 'log_standard' applies sign(x)*log1p(|x|) first -- CICFlowMeter features
    (bytes/s, IATs, packet counts) span 9+ orders of magnitude and a plain z-score leaves almost all
    mass at ~0 with a handful of extreme outliers."""
    if method == "log_standard":
        X = np.sign(X) * np.log1p(np.abs(X))
    mu = X[train_idx].mean(axis=0)
    sd = X[train_idx].std(axis=0) + 1e-6
    return ((X - mu) / sd).astype(np.float32)


# ----------------------------------------------------------------------
def load_pool(cfg: dict, rng: np.random.Generator) -> FlowPool:
    src = cfg["data"]["source"]
    if src == "ciciot2023":
        from .ciciot import load_ciciot
        return load_ciciot(cfg, rng)
    if src == "iotdiad":
        from .iotdiad import load_iotdiad
        return load_iotdiad(cfg, rng)
    if src == "toniot":
        from .toniot import load_toniot_network
        return load_toniot_network(cfg, rng)
    if src == "synthetic":
        from .synthetic import load_synthetic
        return load_synthetic(cfg, rng)
    raise ValueError(f"unknown data.source {src}")
