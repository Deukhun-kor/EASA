"""EASA cloud security service (Section 3.6) -- FastAPI.

Endpoints (Table 2):
  GET  /health
  POST /sync/stats        gateway -> cloud : model vector + sample count  (triggers FedAvg when >=2 gateways pending)
  GET  /sync/model        cloud -> gateway : current global model + version
  POST /revocations       gateway -> cloud : publish a revoked credential/device
  GET  /sync/revocations  cloud -> gateway : full revocation list
  POST /audit             gateway -> cloud : level transitions
  GET  /stats             operator view: versions, counts, aggregation history

State is in-process (a single Cloud Run instance with min-instances=1 is used
during experiments so that state persists and cold starts do not pollute RTT).
For durability swap `Store` for Firestore/DynamoDB -- the interface is tiny.
Auth: X-API-Key header compared against env EASA_API_KEY.
"""
from __future__ import annotations

import base64
import os
import threading
import time

import numpy as np
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

API_KEY = os.environ.get("EASA_API_KEY", "")
MIN_GATEWAYS_FOR_AGG = int(os.environ.get("EASA_MIN_GATEWAYS", "2"))
WEIGHTING = os.environ.get("EASA_FEDAVG_WEIGHTING", "samples")

app = FastAPI(title="EASA Cloud Security Service", version="0.1.0")


def auth(x_api_key: str = Header(default="")):
    if not API_KEY or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid API key")


class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.pending: dict[str, tuple[np.ndarray, int, float]] = {}
        self.model: np.ndarray | None = None
        self.version = 0
        self.agg_history: list[dict] = []
        self.revoked: dict[str, dict] = {}
        self.audit: list[dict] = []
        self.started = time.time()

    def push(self, gid: str, vec: np.ndarray, n: int) -> int:
        with self.lock:
            self.pending[gid] = (vec, n, time.time())
            if len(self.pending) >= MIN_GATEWAYS_FOR_AGG:
                vs = np.stack([v for v, _, _ in self.pending.values()])
                ws = np.array([n for _, n, _ in self.pending.values()], dtype=float)
                ws = ws / ws.sum() if WEIGHTING == "samples" else np.full(len(ws), 1.0 / len(ws))
                self.model = (vs * ws[:, None]).sum(0).astype(np.float32)
                self.version += 1
                self.agg_history.append({"version": self.version, "gateways": sorted(self.pending), "t": time.time(),
                                         "dim": int(self.model.size)})
                self.pending.clear()
            return self.version


S = Store()


class StatsIn(BaseModel):
    gateway_id: str
    n_samples: int
    policy_version: int
    vector_b64: str


class RevocationIn(BaseModel):
    gateway_id: str
    device_id: str
    sim_time: float


@app.get("/health")
def health():
    return {"ok": True, "version": S.version, "uptime_s": round(time.time() - S.started, 1)}


@app.post("/sync/stats", dependencies=[Depends(auth)])
def sync_stats(body: StatsIn):
    vec = np.frombuffer(base64.b64decode(body.vector_b64), dtype=np.float32)
    if S.model is not None and vec.size != S.model.size:
        raise HTTPException(status_code=400, detail=f"vector dim {vec.size} != global {S.model.size}")
    v = S.push(body.gateway_id, vec, body.n_samples)
    return {"accepted": True, "version": v, "pending": len(S.pending)}


@app.get("/sync/model", dependencies=[Depends(auth)])
def sync_model():
    if S.model is None:
        return {"version": 0, "vector_b64": None}
    return {"version": S.version, "vector_b64": base64.b64encode(S.model.tobytes()).decode()}


@app.post("/revocations", dependencies=[Depends(auth)])
def publish_revocation(body: RevocationIn):
    with S.lock:
        S.revoked[body.device_id] = {"by": body.gateway_id, "sim_time": body.sim_time, "wall": time.time()}
    return {"ok": True, "n_revoked": len(S.revoked)}


@app.get("/sync/revocations", dependencies=[Depends(auth)])
def sync_revocations():
    return {"device_ids": sorted(S.revoked), "n": len(S.revoked)}


@app.post("/audit", dependencies=[Depends(auth)])
def audit(event: dict):
    with S.lock:
        event["wall"] = time.time(); S.audit.append(event)
        if len(S.audit) > 200_000: del S.audit[:100_000]
    return {"ok": True}


@app.get("/stats", dependencies=[Depends(auth)])
def stats():
    return {"version": S.version, "pending_gateways": sorted(S.pending), "n_revoked": len(S.revoked),
            "n_audit": len(S.audit), "aggregations": S.agg_history[-20:]}


@app.post("/reset", dependencies=[Depends(auth)])
def reset():
    """Called by the runner between seeds so each run starts from a clean registry."""
    global S
    S = Store()
    return {"ok": True}
