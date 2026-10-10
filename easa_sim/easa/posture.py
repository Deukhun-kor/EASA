"""Device posture model: energy headroom e_d, compute headroom u_d, link quality
q_d and integrity flag iota_d, evolved per epoch from the device's traffic and
enforcement actions. Parameters are per device class (config: posture.classes)
and may be calibrated from TON_IoT telemetry (beacon period / missing ratio)."""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class DeviceClass:
    name: str
    capacity_wh: float
    idle_w: float
    flow_mwh: float


@dataclass
class Posture:
    e: float = 1.0        # energy headroom (fraction of capacity)
    u: float = 1.0        # compute headroom
    q: float = 0.85       # link quality
    iota: int = 1         # firmware integrity (1 ok, 0 tampered)
    energy_spent_mwh: float = 0.0
    reauths: int = 0


class PostureModel:
    def __init__(self, cfg: dict, rng: np.random.Generator):
        p = cfg["posture"]
        self.cfg = p
        self.rng = rng
        names, shares = zip(*[(k, v["share"]) for k, v in p["classes"].items()])
        self.class_names = list(names)
        self.class_probs = np.array(shares) / np.sum(shares)
        self.classes = {k: DeviceClass(k, v["capacity_wh"], v["idle_w"], v["flow_mwh"]) for k, v in p["classes"].items()}

    def assign_class(self) -> DeviceClass:
        return self.classes[self.rng.choice(self.class_names, p=self.class_probs)]

    def init_posture(self) -> Posture:
        lo, hi = self.cfg.get("init_energy_range", [0.6, 1.0])
        return Posture(e=float(self.rng.uniform(lo, hi)), u=1.0,
                       q=float(np.clip(self.rng.normal(self.cfg["link_quality_mean"], self.cfg["link_quality_sigma"]), 0, 1)))

    def step(self, ps: Posture, dc: DeviceClass, n_flows: int, dt: float, did_reauth: bool) -> None:
        """Advance one epoch."""
        if dc.capacity_wh < 900:  # battery device
            spent_mwh = dc.idle_w * dt / 3.6 + n_flows * dc.flow_mwh + (self.cfg["reauth_cost_mwh"] if did_reauth else 0.0)
            ps.energy_spent_mwh += spent_mwh
            ps.e = max(0.0, ps.e - spent_mwh / (dc.capacity_wh * 1000.0))
        else:
            ps.e = 1.0
            if did_reauth:
                ps.energy_spent_mwh += self.cfg["reauth_cost_mwh"]
        # compute headroom: drops with flows, recovers exponentially
        tau = self.cfg["cpu_recovery_tau_s"]
        ps.u = ps.u + (1.0 - ps.u) * (1 - np.exp(-dt / tau)) - self.cfg["cpu_per_flow"] * n_flows
        ps.u = float(np.clip(ps.u, 0.0, 1.0))
        # link quality random walk
        ps.q = float(np.clip(ps.q + self.rng.normal(0, 0.01), 0.0, 1.0))
        if did_reauth:
            ps.reauths += 1

    def score(self, ps: Posture, trust_cfg: dict) -> float:
        return ps.iota * (trust_cfg["alpha_e"] * ps.e + trust_cfg["alpha_u"] * ps.u + trust_cfg["alpha_q"] * ps.q)


def calibrate_from_toniot(telemetry: dict, model: PostureModel) -> dict:
    """Optional: derive per-class link-quality mean from telemetry missing ratio and
    beacon regularity. Returns the overrides applied, for the paper's appendix."""
    overrides = {}
    for name, df in telemetry.items():
        miss = float(df.isna().mean().mean()) if len(df) else 0.0
        q = float(np.clip(1.0 - 2.0 * miss, 0.5, 0.98))
        overrides[name] = {"link_quality_mean": q}
    if overrides:
        model.cfg["link_quality_mean"] = float(np.mean([v["link_quality_mean"] for v in overrides.values()]))
    return overrides
