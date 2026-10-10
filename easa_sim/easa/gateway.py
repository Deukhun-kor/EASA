"""Gateway: owns N devices, a detector, trust+policy engines, and a cloud link.
Runs the Algorithm-1 loop once per epoch for every device."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import numpy as np

from .cloud import CloudBase
from .data.pool import BENIGN, FlowPool
from .detector import make_detector
from .policy import L2, L3, PolicyEngine, PolicyState
from .posture import DeviceClass, Posture, PostureModel
from .replay import Cursor, ReplayBank
from .scenario import Campaign
from .trust import TrustEngine, TrustState

log = logging.getLogger(__name__)


@dataclass
class Device:
    idx: int
    did: str
    dclass: DeviceClass
    posture: Posture
    trust: TrustState = field(default_factory=TrustState)
    policy: PolicyState = field(default_factory=PolicyState)
    # per-epoch bookkeeping
    truth_attacking: bool = False
    truth_family: str = BENIGN
    credential: str = ""
    flows_this_epoch: int = 0
    bytes_uplink: float = 0.0
    log_rows: list = field(default_factory=list)
    # replay state
    ip: str = ""
    benign_cur: Cursor | None = None
    attack_cur: Cursor | None = None
    attack_cur_family: str = ""
    ip_index: int = -1


class Gateway:
    def __init__(self, gid: int, cfg: dict, pool: FlowPool, cloud: CloudBase, rng: np.random.Generator,
                 holdout: list[str], seed: int, replay: ReplayBank | None = None, device_ip_indices: list[int] | None = None):
        self.gid = gid
        self.name = f"g{gid}"
        self.cfg = cfg
        self.pool = pool
        self.cloud = cloud
        self.rng = rng
        self.holdout = holdout
        top = cfg["topology"]
        self.epoch = top["epoch_s"]
        self.window = top["window_s"]
        self.pmodel = PostureModel(cfg, rng)
        self.replay = replay if (replay is not None and replay.enabled) else None
        if self.replay is not None:
            ids = device_ip_indices or []
            self.devices = [Device(i, f"{self.name}-d{i:03d}", self.pmodel.assign_class(), self.pmodel.init_posture(),
                                   ip=self.replay.device_ips[k], benign_cur=self.replay.benign_cursor(k, rng), ip_index=k)
                            for i, k in enumerate(ids)]
        else:
            self.devices = [Device(i, f"{self.name}-d{i:03d}", self.pmodel.assign_class(), self.pmodel.init_posture())
                            for i in range(top["devices_per_gateway"])]
        self.trust = TrustEngine(cfg)
        self.policy = PolicyEngine(cfg)
        det = cfg["detector"]
        # common initialisation across gateways (same seed): a prerequisite for averaging weights (FedAvg)
        self.detector = make_detector(det["kind"], pool.X.shape[1], det, seed, pool.rules_meta)
        self.policy_version = 1
        self.model_version = 0
        self.revoked: set[str] = set()
        self.last_model_sync = 0.0
        self.last_rev_poll = 0.0
        self.last_stats = 0.0
        self.window_buf: dict[int, list[np.ndarray]] = {d.idx: [] for d in self.devices}

    # ------------------------------------------------------------------
    def reset_state(self, segment: str = "eval") -> None:
        """Fresh device/trust/policy state (detector and thresholds kept). segment = "cal" replays the calibration
        segment of each device's trace (benign pass), "eval" the chronologically later evaluation segment."""
        for d in self.devices:
            d.trust = TrustState(); d.policy = PolicyState(); d.posture = self.pmodel.init_posture()
            d.log_rows = []; d.bytes_uplink = 0.0; d.flows_this_epoch = 0
            d.truth_attacking = False; d.truth_family = BENIGN; d.credential = d.did
            d.attack_cur = None; d.attack_cur_family = ""
            if self.replay is not None and d.benign_cur is not None:
                d.benign_cur = self.replay.benign_cursor(d.ip_index, self.rng, segment) if d.ip_index >= 0 \
                    else Cursor(d.benign_cur.tr, self.rng)
        self.window_buf = {d.idx: [] for d in self.devices}
        self.revoked = set()
        self.last_model_sync = self.last_rev_poll = self.last_stats = 0.0

    def train_local(self, epochs: int | None = None) -> None:
        idx = self.pool.train_split_for_gateway(self.holdout)
        X, y = self.pool.X[idx], self.pool.y[idx]
        log.info("%s local training on %d rows (holdout=%s, epochs=%s)", self.name, len(idx), self.holdout,
                 epochs or self.cfg["detector"][self.cfg["detector"]["kind"]].get("epochs", "default") if self.cfg["detector"]["kind"] == "mlp" else "n/a")
        self.detector.fit(X, y, epochs=epochs)

    def val_report(self) -> str:
        """Per-family recall (and benign FPR) on the validation split at p>=0.5 -- detector health check."""
        parts = []
        for fam in ["Benign"] + list(self.pool.families()):
            idx = self.pool.idx_where("val", fam)
            if len(idx) == 0:
                idx = self.pool.idx_where("val"); idx = idx[self.pool.y[idx] == 0] if fam == "Benign" else idx[:0]
            if len(idx) == 0: continue
            idx = idx if len(idx) <= 20_000 else self.rng.choice(idx, size=20_000, replace=False)
            p = self.detector.predict_proba(self.pool.X[idx])
            tag = "*" if fam in self.holdout else ""
            parts.append(f"{fam}{tag}={(p >= 0.5).mean():.2f}")
        return " ".join(parts)

    def finetune_local(self) -> None:
        if not self.detector.federatable or int(self.cfg["detector"].get("local_finetune_epochs", 0)) <= 0: return
        idx = self.pool.train_split_for_gateway(self.holdout)
        sub = self.rng.choice(idx, size=min(len(idx), 50_000), replace=False)
        self.detector.fit(self.pool.X[sub], self.pool.y[sub], epochs=self.cfg["detector"]["local_finetune_epochs"])

    # ------------------------------------------------------------------
    def _draw_flows(self, dev: Device, campaigns: list[Campaign], t: float) -> tuple[np.ndarray, int]:
        top = self.cfg["topology"]
        active = [c for c in campaigns if c.gateway == self.gid and c.active(t) and dev.idx in c.devices]
        dev.truth_attacking = bool(active)
        dev.truth_family = active[0].family if active else BENIGN
        dev.credential = active[0].credential_id if active else dev.did     # compromised devices present the campaign credential
        if active and active[0].family == "FirmwareTamper":
            dev.posture.iota = 0
        traffic_fam = dev.truth_family if dev.truth_family in self.pool.families() else BENIGN

        if self.replay is not None:
            # ---- trace replay: benign cursor always runs; an attack cursor is attached while a traffic campaign is active
            rows = dev.benign_cur.take(t, t + self.epoch) if dev.benign_cur else np.empty(0, dtype=np.int64)
            if traffic_fam != BENIGN:
                if dev.attack_cur is None or dev.attack_cur_family != traffic_fam:
                    dev.attack_cur = self.replay.attack_cursor(traffic_fam, self.rng); dev.attack_cur_family = traffic_fam
                if dev.attack_cur is not None:
                    rows = np.concatenate([rows, dev.attack_cur.take(t, t + self.epoch)])
            else:
                dev.attack_cur = None
            n_emitted = len(rows)
        else:
            # ---- Poisson fallback (synthetic / CIC-IoT-2023 feature pools)
            rate = top["attack_flow_rate_hz"] if traffic_fam != BENIGN else top["benign_flow_rate_hz"]
            n_emitted = int(self.rng.poisson(rate * self.epoch))
            rows = self.pool.sample(self.rng, "test", traffic_fam, n_emitted) if n_emitted else np.empty(0, dtype=np.int64)

        # ---- enforcement acts on the emitted flows
        if dev.policy.level == L3:
            rows = rows[:0]
        elif dev.policy.rate_limit_hz is not None:
            cap = int(dev.policy.rate_limit_hz * self.epoch)
            if len(rows) > cap:          # the PEP drops excess flows uniformly, not "the last ones" (keeps the mix representative)
                rows = rows[np.sort(self.rng.choice(len(rows), size=cap, replace=False))]
        n = len(rows)
        if n == 0:
            return np.empty((0, self.pool.X.shape[1]), dtype=np.float32), 0
        return self.pool.X[rows], n

    def _push_window(self, dev: Device, Xf: np.ndarray) -> None:
        buf = self.window_buf[dev.idx]
        if len(Xf): buf.append(Xf)
        k = int(self.window / self.epoch)
        if len(buf) > k: del buf[:-k]

    def _window_probs(self) -> dict[int, float]:
        """One batched inference per gateway per epoch over all devices' windows."""
        chunks, owners = [], []
        for dev in self.devices:
            buf = self.window_buf[dev.idx]
            if buf:
                Xw = np.vstack(buf); chunks.append(Xw); owners.append((dev.idx, len(Xw)))
        if not chunks:
            return {d.idx: 0.0 for d in self.devices}
        p = self.detector.predict_proba(np.vstack(chunks))
        tr = self.cfg["trust"]
        agg, k = tr.get("window_agg", "topk"), int(tr.get("window_topk", 3))
        out, i = {d.idx: 0.0 for d in self.devices}, 0
        for idx, n in owners:
            pw = p[i:i + n]; i += n
            if agg == "mean":            # window average: a few malicious flows are diluted by the device's benign traffic
                out[idx] = float(pw.mean())
            elif agg == "max":           # any single alert drives the score (k = 1)
                out[idx] = float(pw.max())
            else:                        # topk: sum of the k most suspicious flows / k, padded with 0 when the window holds < k flows
                out[idx] = float(np.sort(pw)[-k:].sum() / k)   # == "at least k confident alerts per window" (Snort-style event thresholding)
        return out

    # ------------------------------------------------------------------
    def step(self, t: float, campaigns: list[Campaign]) -> None:
        c = self.cfg["cloud"]
        # -- cloud sync (asynchronous w.r.t. the decision loop; modelled as periodic)
        if self.cloud.sync_model_enabled and t - self.last_model_sync >= c["model_sync_interval_s"]:
            vec, ver = self.cloud.pull_model()
            if vec is not None and ver > self.model_version and self.detector.federatable:
                self.detector.set_vector(vec); self.model_version = ver
            self.last_model_sync = t
        if self.cloud.sync_model_enabled and t - self.last_stats >= c["stats_upload_interval_s"]:
            self.finetune_local()
            self.cloud.push_stats(self.name, self.detector.get_vector(), self.detector.n_samples_seen(), self.policy_version)
            self.last_stats = t
        if self.cloud.revocation_enabled and t - self.last_rev_poll >= c["revocation_poll_interval_s"]:
            self.revoked |= self.cloud.pull_revocations(); self.last_rev_poll = t

        # -- per device decision epoch (Algorithm 1); flows drawn first, then one batched inference
        for dev in self.devices:
            Xf, n = self._draw_flows(dev, campaigns, t)
            dev.flows_this_epoch = n
            self._push_window(dev, Xf)
        probs = self._window_probs()
        for dev in self.devices:
            n = dev.flows_this_epoch
            p_attack = probs[dev.idx]
            s_pos = self.pmodel.score(dev.posture, self.cfg["trust"])
            prev_level = dev.policy.level
            T = self.trust.update(dev.trust, p_attack, s_pos, prev_level,
                                  tau_L1=self.policy.tau.get(1), reset_after=int(self.cfg["policy"].get("history_reset_epochs", 0)))
            # revocation check is by *credential*: a replayed credential is caught only if another
            # gateway's L3 decision reached the cloud registry and this gateway has pulled it
            revoked = dev.credential in self.revoked
            act = self.policy.evaluate(dev.policy, T, dev.posture.iota, revoked, dev.posture.e, t)
            if act.revoke:
                self.revoked.add(dev.credential)
                self.cloud.publish_revocation(self.name, dev.credential, t)
            if dev.policy.level != prev_level and self.cloud.audit_enabled:
                self.cloud.audit({"gateway": self.name, "device": dev.did, "t": t, "from": prev_level,
                                  "to": dev.policy.level, "T": round(T, 4), "policy_version": self.policy_version})
            self.pmodel.step(dev.posture, dev.dclass, n, self.epoch, act.reauth)
            # uplink overhead: posture beacon (48 B) every epoch x telemetry factor, + re-auth handshake (~3 KB)
            dev.bytes_uplink += 48 * dev.policy.telemetry_factor + (3000 if act.reauth else 0)
            dev.log_rows.append((t, dev.truth_attacking, dev.truth_family, p_attack, dev.trust.S_net, dev.trust.S_pos,
                                 dev.trust.S_hist, T, dev.policy.level, int(act.reauth), int(act.deferred_stepup),
                                 dev.posture.e, dev.posture.u, dev.posture.q, dev.posture.iota, n))
