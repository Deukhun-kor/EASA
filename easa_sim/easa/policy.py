"""Policy Decision Point and Enforcement Point (Section 3.4, Table 1).

Levels: 0 Normal, 1 Observe, 2 Restrict, 3 Quarantine.
Promotion is immediate when T < tau_enter[k]; relaxation requires T > tau_enter[k]+delta
for h consecutive epochs (hysteresis). Energy-aware action selection at L2.
"""
from __future__ import annotations

from dataclasses import dataclass, field

L0, L1, L2, L3 = 0, 1, 2, 3
LEVEL_NAMES = {L0: "Normal", L1: "Observe", L2: "Restrict", L3: "Quarantine"}


@dataclass
class PolicyState:
    level: int = L0
    above_exit_count: int = 0
    quarantined_at: float | None = None
    token_ttl_factor: float = 1.0
    telemetry_factor: float = 1.0
    rate_limit_hz: float | None = None
    scope_restricted: bool = False
    pending_stepup: bool = False
    n_deferred: int = 0            # step-ups deferred (energy-aware)
    n_deferred_executed: int = 0   # ... later executed because e_d recovered while still restricted
    n_deferred_cancelled: int = 0  # ... cancelled because the device relaxed below L2 first
    clean_count: int = 0           # consecutive restricted epochs whose network score alone is at the L0 level
    n_clean_releases: int = 0      # bounded-dwell releases (policy.clean_release_epochs > 0)
    transitions: list = field(default_factory=list)


@dataclass
class Action:
    level: int
    reauth: bool = False
    rate_limit_hz: float | None = None
    scope_restricted: bool = False
    drop: bool = False
    revoke: bool = False
    deferred_stepup: bool = False


class PolicyEngine:
    def __init__(self, cfg: dict):
        p = cfg["policy"]
        self.cfg = p
        self.disabled = bool(p.get("disabled", False))   # B0: never changes level
        self.binary = bool(p.get("binary", False))        # B1/B2: only L0 <-> L3 (allow/block)
        self.tau = {L1: p["tau_enter"]["L1"], L2: p["tau_enter"]["L2"], L3: p["tau_enter"]["L3"]}
        self.delta = p["hysteresis_delta"]
        self.h = p["h_epochs"]
        self.energy_floor = cfg["posture"]["energy_floor"]
        self.energy_aware = bool(p.get("energy_aware", True))   # False: always re-handshake on L2 entry (B3)
        # Bounded dwell (revision r1, editor point 4 / R4): a device held at L2 whose *network* score alone has been at
        # the L0 level (S_net >= tau_L1) for this many consecutive epochs is released to L1 regardless of T, and the
        # release is logged for the operator (n_clean_releases). 0 = off (protocol v3 main grid). L3 is unaffected:
        # quarantine remains absorbing within a run and is released by the policy timer or an operator.
        self.clean_release = int(p.get("clean_release_epochs", 0))
        # Evidence-based release (revision r1, editor point 4): the relaxation test compares the *network* score alone
        # (S_net) with the exit threshold instead of the composite T. Entry still uses T. Removes the asymmetry that the
        # decayed history term creates (with S_hist = 0 the composite needs S_net > (tau_L1 - w_pos S_pos)/w_net ~ 0.84
        # to leave L2, while entry happened at T < tau_L2). "T" = protocol v3 default.
        self.exit_on = str(p.get("exit_on", "T"))
        # Protocol v4 (revision r1): per-device thresholds. When set, tau_by_device[did] = ({1: .., 2: .., 3: ..}, delta)
        # overrides the fleet thresholds for that device (device-level baseline, calibrated from the device's own
        # benign calibration segment at a quantile level shared by every device; see runner.py).
        self.tau_by_device: dict = {}

    def thresholds(self, did: str | None):
        t = self.tau_by_device.get(did) if did is not None else None
        return (t[0], t[1]) if t is not None else (self.tau, self.delta)

    def tau_L1_for(self, did: str | None) -> float:
        return self.thresholds(did)[0][L1]

    # ------------------------------------------------------------------
    def _target_level(self, T: float, tau: dict | None = None) -> int:
        tau = tau or self.tau
        if T < tau[L3]: return L3
        if T < tau[L2]: return L2
        if T < tau[L1]: return L1
        return L0

    def evaluate(self, ps: PolicyState, T: float, iota: int, revoked: bool, e_d: float, now: float,
                 s_net: float | None = None, did: str | None = None) -> Action:
        """MapWithHysteresis + SelectAction. Returns the action to enforce (level may be unchanged)."""
        if self.disabled:
            return Action(level=L0)
        tau, delta = self.thresholds(did)
        prev = ps.level
        if iota == 0 or revoked:
            target = L3
        else:
            target = self._target_level(T, tau)
            if self.binary:
                target = L3 if target >= L2 else L0
        # bounded dwell: clean network evidence for clean_release consecutive epochs releases an L2 device to L1
        if self.clean_release > 0 and prev == L2 and s_net is not None and iota != 0 and not revoked:
            ps.clean_count = ps.clean_count + 1 if s_net >= tau[L1] else 0
            if ps.clean_count >= self.clean_release:
                ps.clean_count = 0; ps.n_clean_releases += 1
                target = min(target, L1)
                ps.level = L1; ps.above_exit_count = 0
                prev_for_log = prev; prev = L1   # treat as already relaxed; the transition is recorded below
                ps.transitions.append((now, prev_for_log, L1))
        elif prev != L2:
            ps.clean_count = 0
        # promotion: immediate
        if target > prev:
            ps.level = target; ps.above_exit_count = 0
        # relaxation: hysteresis
        elif target < prev:
            exit_thr = tau.get(prev, 1.0) + delta
            exit_score = s_net if (self.exit_on == "S_net" and s_net is not None) else T
            if prev == L3 and ps.quarantined_at is not None and now - ps.quarantined_at < self.cfg["l3_release_after_s"] and revoked:
                ps.above_exit_count = 0
            elif exit_score > exit_thr:
                ps.above_exit_count += 1
                if ps.above_exit_count >= self.h:
                    ps.level = max(target, prev - 1) if not self.binary else L0
                    ps.above_exit_count = 0
            else:
                ps.above_exit_count = 0
        else:
            ps.above_exit_count = 0

        act = Action(level=ps.level)
        if ps.level != prev:
            ps.transitions.append((now, prev, ps.level))
            if ps.level == L3:
                ps.quarantined_at = now
        # enforcement side-effects (cumulative)
        ps.token_ttl_factor = self.cfg["l1_token_ttl_factor"] if ps.level >= L1 else 1.0
        ps.telemetry_factor = self.cfg["l1_telemetry_factor"] if ps.level >= L1 else 1.0
        if ps.level >= L2:
            act.rate_limit_hz = self.cfg["l2_rate_limit_hz"]; act.scope_restricted = True
            # energy-aware step-up: defer crypto re-handshake when below the energy floor
            if ps.level == L2 and prev < L2:
                if self.energy_aware and e_d < self.energy_floor:
                    act.deferred_stepup = True; ps.pending_stepup = True; ps.n_deferred += 1
                else:
                    act.reauth = True
            elif ps.pending_stepup and e_d >= self.energy_floor:
                act.reauth = True; ps.pending_stepup = False; ps.n_deferred_executed += 1
        else:
            if ps.pending_stepup:
                ps.n_deferred_cancelled += 1
            ps.pending_stepup = False
        if ps.level == L3:
            act.drop = True
            act.revoke = (prev != L3)
        ps.rate_limit_hz = act.rate_limit_hz
        ps.scope_restricted = act.scope_restricted
        return act
