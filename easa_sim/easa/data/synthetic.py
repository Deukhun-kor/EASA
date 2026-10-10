"""Synthetic flow pool for smoke tests and CI. Mimics the statistical shape of
CIC-IoT-2023 (7 attack families, 46 features) with family-specific shifts so
that a learned detector is non-trivial but learnable. Never used for paper
results -- only to validate the pipeline before the real data are in place."""
from __future__ import annotations

import logging

import numpy as np

from .pool import BENIGN, FlowPool, make_splits, scale_fit_transform

log = logging.getLogger(__name__)

FAMILIES = ["DDoS", "DoS", "Mirai", "Recon", "Spoofing", "Web", "BruteForce"]
D = 46


def load_synthetic(cfg: dict, rng: np.random.Generator, n_benign: int = 60_000, n_per_attack: int = 8_000) -> FlowPool:
    rows, fams = [], []
    base = rng.normal(0, 1, size=(n_benign, D)).astype(np.float32)
    rows.append(base); fams += [BENIGN] * n_benign
    for k, fam in enumerate(FAMILIES):
        shift = np.zeros(D, dtype=np.float32)
        # each family perturbs a different subset of features, with overlap to make it harder
        idx = rng.choice(D, size=8, replace=False)
        shift[idx] = rng.normal(1.5, 0.5, size=8) * rng.choice([-1, 1], size=8)
        noise_scale = 1.0 + 0.3 * k
        Xa = (rng.normal(0, noise_scale, size=(n_per_attack, D)) + shift).astype(np.float32)
        rows.append(Xa); fams += [fam] * n_per_attack
    X = np.vstack(rows)
    fam = np.array(fams, dtype=str)
    y = (fam != BENIGN).astype(np.int8)
    tr, va, te = make_splits(rng, len(y), cfg["data"]["test_fraction"], cfg["data"]["val_fraction"], fam)
    names = [f"f{i}" for i in range(D)]
    # pretend the first few columns are the rule columns
    rule_cols = {"Rate": 0, "Srate": 1, "syn_count": 2, "rst_count": 3, "IAT": 4, "Number": 5, "Tot sum": 6}
    Xs = scale_fit_transform(X, tr, "standard")
    pool = FlowPool(Xs, y, fam, names, tr, va, te,
                    rules_meta={"cols": rule_cols, "raw_mu": X[tr].mean(0), "raw_sd": X[tr].std(0) + 1e-6,
                                "dup_ratio": 0.0})
    log.info("SYNTHETIC pool (smoke test only): %s", pool.summary())
    return pool
