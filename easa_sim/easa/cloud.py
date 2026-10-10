"""Cloud security service clients (Section 3.6).

Two implementations behind one interface:
  HttpCloud  -- talks to the real service (cloud_service/app.py) deployed in a
                Seoul region; every call's wall-clock RTT is recorded.
  LocalCloud -- in-process mock with identical semantics (EASA-C ablation uses
                NullCloud, which does nothing).

Modes (cloud.mode): http | local | none | model_only | revocation_only
"""
from __future__ import annotations

import base64
import logging
import os
import time

import numpy as np

log = logging.getLogger(__name__)

try:
    import requests
    _HAS_REQ = True
except Exception:  # pragma: no cover
    _HAS_REQ = False


def _b64(v: np.ndarray) -> str:
    return base64.b64encode(v.astype(np.float32).tobytes()).decode()


def _unb64(s: str) -> np.ndarray:
    return np.frombuffer(base64.b64decode(s), dtype=np.float32)


class CloudBase:
    rtts: list[tuple[str, float]]
    def __init__(self, mode: str):
        self.mode = mode
        self.rtts = []
        self.sync_model_enabled = mode in ("http", "local", "model_only")
        self.revocation_enabled = mode in ("http", "local", "revocation_only")
        self.audit_enabled = mode in ("http", "local")
    def push_stats(self, gateway_id: str, vector: np.ndarray, n_samples: int, policy_version: int) -> None: ...
    def pull_model(self) -> tuple[np.ndarray | None, int]: ...
    def publish_revocation(self, gateway_id: str, device_id: str, t: float) -> None: ...
    def pull_revocations(self) -> set[str]: ...
    def audit(self, event: dict) -> None: ...
    def health(self) -> bool: return True


class NullCloud(CloudBase):
    def __init__(self): super().__init__("none")
    def push_stats(self, *a, **k): pass
    def pull_model(self): return None, 0
    def publish_revocation(self, *a, **k): pass
    def pull_revocations(self): return set()
    def audit(self, event): pass


class LocalCloud(CloudBase):
    """In-process mock: FedAvg of uploaded vectors, revocation registry, audit list."""
    def __init__(self, mode: str = "local", weighting: str = "samples", min_gateways: int = 2):
        super().__init__(mode)
        self.weighting = weighting
        self.min_gateways = min_gateways
        self.pending: dict[str, tuple[np.ndarray, int]] = {}
        self.model: np.ndarray | None = None
        self.version = 0
        self.revoked: set[str] = set()
        self.audit_log: list[dict] = []

    def push_stats(self, gateway_id, vector, n_samples, policy_version):
        if not self.sync_model_enabled: return
        self.pending[gateway_id] = (vector.astype(np.float32), int(n_samples))
        if len(self.pending) >= self.min_gateways:
            self._aggregate()

    def _aggregate(self):
        vs = np.stack([v for v, _ in self.pending.values()])
        ws = np.array([n for _, n in self.pending.values()], dtype=float)
        ws = ws / ws.sum() if self.weighting == "samples" else np.full(len(ws), 1 / len(ws))
        self.model = (vs * ws[:, None]).sum(0).astype(np.float32)
        self.version += 1
        self.pending.clear()

    def pull_model(self):
        return (self.model, self.version) if self.sync_model_enabled else (None, 0)

    def publish_revocation(self, gateway_id, device_id, t):
        if self.revocation_enabled: self.revoked.add(device_id)

    def pull_revocations(self):
        return set(self.revoked) if self.revocation_enabled else set()

    def audit(self, event):
        if self.audit_enabled: self.audit_log.append(event)


class HttpCloud(CloudBase):
    """Real service. Set EASA_API_KEY in the environment; base_url from config."""
    def __init__(self, base_url: str, api_key_env: str, timeout_s: float, mode: str = "http",
                 retries: int = 3, backoff_s: float = 1.0):
        super().__init__(mode)
        self.retries = int(retries); self.backoff = float(backoff_s)
        self.n_errors = 0            # calls that failed after all retries (the gateway then carries on with its last state)
        self.n_retries = 0
        if not _HAS_REQ:
            raise RuntimeError("pip install requests")
        self.base = base_url.rstrip("/")
        self.key = os.environ.get(api_key_env, "")
        if not self.key:
            log.warning("env %s not set -- requests will be rejected by the service", api_key_env)
        self.timeout = timeout_s
        self.s = requests.Session()
        self.s.headers.update({"X-API-Key": self.key, "Content-Type": "application/json"})
        self.model_version = 0

    def _call(self, method: str, path: str, critical: bool = False, **kw):
        """One service call with retries. Transient failures (timeouts, 5xx, connection resets) are retried
        with exponential back-off; if every attempt fails the call is logged, counted in n_errors and an
        empty response is returned so the decision loop keeps running on its last synced state -- exactly
        what a real gateway does during a short cloud hiccup. critical=True re-raises instead (health, reset)."""
        last = None
        for attempt in range(self.retries + 1):
            t0 = time.perf_counter()
            try:
                r = self.s.request(method, self.base + path, timeout=self.timeout, **kw)
                self.rtts.append((path, time.perf_counter() - t0))
                if r.status_code >= 500:
                    raise requests.HTTPError(f"{r.status_code} from {path}", response=r)
                r.raise_for_status()
                return r.json() if r.content else {}
            except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as e:
                last = e
                if isinstance(e, requests.HTTPError) and e.response is not None and 400 <= e.response.status_code < 500:
                    raise                                   # auth / bad request: not transient
                if attempt < self.retries:
                    self.n_retries += 1
                    time.sleep(self.backoff * (2 ** attempt))
        self.n_errors += 1
        log.warning("cloud call %s %s failed after %d attempts (%s) -- continuing with last synced state",
                    method, path, self.retries + 1, last)
        if critical:
            raise RuntimeError(f"cloud call {path} failed: {last}")
        return {}

    def health(self) -> bool:
        try:
            return self._call("GET", "/health", critical=True).get("ok", False)
        except Exception as e:  # noqa: BLE001
            log.error("cloud health check failed: %s", e); return False

    def push_stats(self, gateway_id, vector, n_samples, policy_version):
        if not self.sync_model_enabled: return
        self._call("POST", "/sync/stats", json={"gateway_id": gateway_id, "n_samples": int(n_samples),
                                                 "policy_version": int(policy_version), "vector_b64": _b64(vector)})

    def pull_model(self):
        if not self.sync_model_enabled: return None, 0
        j = self._call("GET", "/sync/model")
        if not j.get("vector_b64"): return None, int(j.get("version", 0))
        return _unb64(j["vector_b64"]), int(j["version"])

    def publish_revocation(self, gateway_id, device_id, t):
        if not self.revocation_enabled: return
        self._call("POST", "/revocations", json={"gateway_id": gateway_id, "device_id": device_id, "sim_time": float(t)})

    def pull_revocations(self):
        if not self.revocation_enabled: return set()
        return set(self._call("GET", "/sync/revocations").get("device_ids", []))

    def audit(self, event):
        if self.audit_enabled: self._call("POST", "/audit", json=event)

    def reset(self) -> None:
        """Clear server-side state between seeds (not counted in RTT stats)."""
        self._call("POST", "/reset", critical=True); self.rtts.pop()

    def rtt_summary(self) -> dict:
        if not self.rtts: return {"n_calls": 0, "n_cloud_errors": self.n_errors, "n_cloud_retries": self.n_retries}
        arr = np.array([r for _, r in self.rtts]) * 1000
        return {"n_calls": len(arr), "rtt_ms_mean": float(arr.mean()), "rtt_ms_p50": float(np.percentile(arr, 50)),
                "rtt_ms_p95": float(np.percentile(arr, 95)), "rtt_ms_max": float(arr.max()),
                "n_cloud_errors": self.n_errors, "n_cloud_retries": self.n_retries}


def make_cloud(cfg: dict) -> CloudBase:
    """mode selects *which* cloud functions exist (none | model_only | revocation_only | http=all | local=all);
    transport selects *where* they run: http = the deployed service, local = in-process mock.
    mode=local always uses the mock (handy for offline runs: --set cloud.mode=local)."""
    c = cfg["cloud"]
    mode = c["mode"]
    if mode == "none":
        return NullCloud()
    transport = c.get("transport", "http")
    if mode != "local" and transport == "http" and "REPLACE-ME" not in c.get("base_url", "REPLACE-ME"):
        return HttpCloud(c["base_url"], c["api_key_env"], c["timeout_s"], mode="http" if mode == "local" else mode,
                         retries=int(c.get("retries", 3)), backoff_s=float(c.get("retry_backoff_s", 1.0)))
    # in-process mock with the same feature gating
    return LocalCloud(mode="local" if mode == "http" else mode, weighting=c.get("fedavg_weighting", "samples"),
                      min_gateways=int(c.get("min_gateways", cfg["topology"]["n_gateways"])))
