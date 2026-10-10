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

    def train_split_for_gateway(self, holdout: list[str]) -> np.ndarray:
        """Local training rows for a gateway: all benign + attacks NOT in holdout."""
        tr = self.train_idx
        keep = ~np.isin(self.family[tr], holdout)
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
