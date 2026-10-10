"""Per-flow attack-probability detectors f_theta.

Three kinds share one interface (fit / predict_proba / get_vector / set_vector):

* MLPDetector   -- two-layer MLP. Parameters are a flat vector so the cloud can
                   FedAvg them across gateways. Uses PyTorch on CUDA when
                   available (RTX 5080), otherwise sklearn's MLPClassifier.
* XGBDetector   -- gradient-boosted trees (centralised upper bound / B1).
                   Not federatable; the cloud simply redistributes the best model.
* RuleDetector  -- deterministic freshness/context rules in the spirit of
                   YB-IoT-CG (B2): z-score thresholds on rate/SYN/RST/IAT columns.
"""
from __future__ import annotations

import logging
from typing import Protocol

import numpy as np

log = logging.getLogger(__name__)

try:  # optional GPU path
    import torch
    import torch.nn as nn
    _HAS_TORCH = True
except Exception:  # pragma: no cover
    _HAS_TORCH = False

try:
    import xgboost as xgb
    _HAS_XGB = True
except Exception:  # pragma: no cover
    _HAS_XGB = False


class Detector(Protocol):
    federatable: bool
    def fit(self, X: np.ndarray, y: np.ndarray, epochs: int | None = None) -> None: ...
    def predict_proba(self, X: np.ndarray) -> np.ndarray: ...
    def get_vector(self) -> np.ndarray: ...
    def set_vector(self, v: np.ndarray) -> None: ...
    def n_samples_seen(self) -> int: ...


# ----------------------------------------------------------------------
class MLPDetector:
    federatable = True

    def __init__(self, d_in: int, cfg: dict, seed: int):
        self.cfg = cfg
        self.d_in = d_in
        self.seed = seed
        self._n_seen = 0
        self.backend = "torch" if _HAS_TORCH else "sklearn"
        if self.backend == "torch":
            torch.manual_seed(seed)
            dev = cfg.get("device", "cuda")
            self.device = torch.device(dev if (dev == "cuda" and torch.cuda.is_available()) else "cpu")
            layers, prev = [], d_in
            for h in cfg["hidden"]:
                layers += [nn.Linear(prev, h), nn.ReLU(), nn.Dropout(cfg.get("dropout", 0.0))]
                prev = h
            layers += [nn.Linear(prev, 1)]
            self.net = nn.Sequential(*layers).to(self.device)
            self.opt = torch.optim.Adam(self.net.parameters(), lr=cfg["lr"])
            self.loss = nn.BCEWithLogitsLoss()
        else:
            from sklearn.neural_network import MLPClassifier
            self.clf = MLPClassifier(hidden_layer_sizes=tuple(cfg["hidden"]), learning_rate_init=cfg["lr"],
                                     max_iter=1, warm_start=True, random_state=seed)
            self._init_done = False
        log.info("MLPDetector backend=%s device=%s", self.backend, getattr(self, "device", "cpu"))

    # -- training ------------------------------------------------------
    def fit(self, X: np.ndarray, y: np.ndarray, epochs: int | None = None) -> None:
        epochs = epochs or self.cfg["epochs"]
        self._n_seen += len(y)
        if self.backend == "torch":
            Xt = torch.from_numpy(X).to(self.device)
            yt = torch.from_numpy(y.astype(np.float32)).to(self.device)
            bs = self.cfg["batch_size"]
            n = len(yt)
            self.net.train()
            for _ in range(epochs):
                perm = torch.randperm(n, device=self.device)
                for i in range(0, n, bs):
                    b = perm[i:i + bs]
                    self.opt.zero_grad()
                    out = self.net(Xt[b]).squeeze(-1)
                    l = self.loss(out, yt[b])
                    l.backward()
                    self.opt.step()
        else:
            for _ in range(epochs):
                self.clf.partial_fit(X, y, classes=np.array([0, 1]))
            self._init_done = True

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if self.backend == "torch":
            self.net.eval()
            with torch.no_grad():
                out = torch.sigmoid(self.net(torch.from_numpy(X).to(self.device)).squeeze(-1))
            return out.cpu().numpy().astype(np.float32)
        if not getattr(self, "_init_done", False):
            return np.full(len(X), 0.5, dtype=np.float32)
        return self.clf.predict_proba(X)[:, 1].astype(np.float32)

    # -- federation ----------------------------------------------------
    def get_vector(self) -> np.ndarray:
        if self.backend == "torch":
            return torch.cat([p.detach().flatten() for p in self.net.parameters()]).cpu().numpy()
        return np.concatenate([w.flatten() for w in self.clf.coefs_] + [b.flatten() for b in self.clf.intercepts_])

    def set_vector(self, v: np.ndarray) -> None:
        if self.backend == "torch":
            i = 0
            with torch.no_grad():
                for p in self.net.parameters():
                    n = p.numel()
                    p.copy_(torch.from_numpy(v[i:i + n]).view_as(p).to(self.device)); i += n
        else:
            i = 0
            for k, w in enumerate(self.clf.coefs_):
                n = w.size; self.clf.coefs_[k] = v[i:i + n].reshape(w.shape); i += n
            for k, b in enumerate(self.clf.intercepts_):
                n = b.size; self.clf.intercepts_[k] = v[i:i + n].reshape(b.shape); i += n

    def n_samples_seen(self) -> int:
        return self._n_seen


# ----------------------------------------------------------------------
class XGBDetector:
    federatable = False

    def __init__(self, d_in: int, cfg: dict, seed: int):
        if not _HAS_XGB:
            raise RuntimeError("xgboost not installed; pip install xgboost")
        # native Booster API (xgb.train): same model as XGBClassifier(objective=binary:logistic, tree_method=hist)
        # but without the scikit-learn wrapper, so scikit-learn is not required at all
        self.params = {"objective": "binary:logistic", "max_depth": int(cfg["max_depth"]), "eta": float(cfg["learning_rate"]),
                       "tree_method": "hist", "device": cfg.get("device", "cuda"), "seed": int(seed), "eval_metric": "logloss"}
        self.n_rounds = int(cfg["n_estimators"])
        self.booster: "xgb.Booster | None" = None
        self._n_seen = 0

    def fit(self, X, y, epochs=None):
        dtrain = xgb.DMatrix(np.asarray(X, dtype=np.float32), label=np.asarray(y, dtype=np.float32))
        self.booster = xgb.train(self.params, dtrain, num_boost_round=self.n_rounds)
        self._n_seen += len(y)

    def predict_proba(self, X):
        if self.booster is None:
            return np.zeros(len(X), dtype=np.float32)
        return self.booster.predict(xgb.DMatrix(np.asarray(X, dtype=np.float32))).astype(np.float32)

    def get_vector(self):  # opaque blob transported as bytes->uint8 for the cloud to redistribute
        return np.frombuffer(self.booster.save_raw("ubj"), dtype=np.uint8)

    def set_vector(self, v):
        if self.booster is None:
            self.booster = xgb.Booster(self.params)
        self.booster.load_model(bytearray(v.tobytes()))

    def n_samples_seen(self):
        return self._n_seen


# ----------------------------------------------------------------------
class RuleDetector:
    """B2: deterministic screening. Flags a window as anomalous when any of the
    rate/SYN/RST/IAT z-scores exceeds k sigma; outputs a graded probability so
    it can drive the same trust pipeline."""
    federatable = False

    def __init__(self, d_in: int, cfg: dict, seed: int, rules_meta: dict | None = None, k: float = 3.0):
        self.cols = list((rules_meta or {}).get("cols", {}).values())
        self.k = k
        self._n_seen = 0

    def fit(self, X, y, epochs=None):
        self._n_seen += len(y)   # rules are not trained

    def predict_proba(self, X):
        if not self.cols:
            return np.zeros(len(X), dtype=np.float32)
        z = np.abs(X[:, self.cols])              # X is already z-scored
        score = np.clip((z.max(axis=1) - self.k) / self.k, 0, 1)
        return score.astype(np.float32)

    def get_vector(self): return np.zeros(1, dtype=np.float32)
    def set_vector(self, v): pass
    def n_samples_seen(self): return self._n_seen


# ----------------------------------------------------------------------
def make_detector(kind: str, d_in: int, cfg: dict, seed: int, rules_meta: dict | None = None) -> Detector:
    if kind == "mlp":
        return MLPDetector(d_in, cfg["mlp"], seed)
    if kind == "xgb":
        return XGBDetector(d_in, cfg["xgb"], seed)
    if kind == "rules":
        return RuleDetector(d_in, {}, seed, rules_meta)
    raise ValueError(kind)
