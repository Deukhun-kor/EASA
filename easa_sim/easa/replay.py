"""Trace replay for datasets that carry per-flow identity and timestamps (IoT-DIAD 2024).

Design (see paper Sec. 5.1):
  * A simulated device d is anchored to one Benign-chain IP. Its benign traffic is the *test-split*
    rows of that IP, replayed in real time from a random offset into the IP's timeline (per seed),
    so inter-flow gaps are the measured ones. Gaps larger than `gap_cap_s` (idle periods / capture
    breaks) are clipped so one hour of simulation sees one hour of traffic.
  * When d is compromised with family F, it additionally emits the flows of one designated attacker
    of F (dominant_src labelling), replayed the same way from F's test split. Because the LAN uses
    DHCP, attacker identity is only meaningful inside the attack capture; the simulator therefore
    binds "which attacker trace" to the campaign, not to the device IP.
  * Enforcement acts on the emitted flows: L2 rate-limit truncates per-epoch flows, L3 drops them.
Protocol v3 (review round 2, 2026-10-09):
  * replay.availability = "end" (default): a flow record is emitted at Timestamp + Flow Duration, i.e. when an online
    extractor would have its completed statistics ("start" reproduces protocol v2: completed statistics at flow start).
  * replay.calibration_fraction = f (default 1/3): the first f of each device's test-split timeline is reserved for the
    benign calibration pass and never replayed in the evaluation; the remaining 1-f is the evaluation trace. f = 0
    reproduces protocol v2 (same trace pool, different phase).
Fallback: if the pool has no replay metadata, Gateway uses Poisson sampling (synthetic / CIC-IoT-2023).
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .data.pool import BENIGN, FlowPool


@dataclass
class Trace:
    rows: np.ndarray        # pool row indices, time-ordered
    t: np.ndarray           # replay time (s) of each row, starting at 0, gaps clipped
    duration: float


def _build(rows: np.ndarray, abs_t: np.ndarray, gap_cap: float) -> Trace | None:
    """abs_t is the *availability* time of each row (start, or start + duration under protocol v3)."""
    if len(rows) == 0:
        return None
    order = rows[np.argsort(abs_t[rows], kind="stable")]
    gaps = np.diff(abs_t[order], prepend=abs_t[order][0])
    gaps = np.clip(gaps, 0.0, gap_cap)
    t = np.cumsum(gaps)
    return Trace(order, t, float(t[-1]) if len(t) else 0.0)


class Cursor:
    """Walks a Trace cyclically from a random phase."""
    def __init__(self, tr: Trace, rng: np.random.Generator):
        self.tr = tr
        self.phase = float(rng.uniform(0, max(tr.duration, 1e-6)))
        self.i = int(np.searchsorted(tr.t, self.phase))
        self.loops = 0

    def take(self, t0: float, t1: float) -> np.ndarray:
        """Rows whose (shifted, cyclic) replay time falls in [t0, t1)."""
        tr, out = self.tr, []
        if tr.duration <= 0:
            return tr.rows[:1] if t1 - t0 > 0 else tr.rows[:0]
        start = self.phase + t0 - self.loops * tr.duration
        end = self.phase + t1 - self.loops * tr.duration
        while True:
            while self.i < len(tr.t) and tr.t[self.i] < end:
                if tr.t[self.i] >= start:
                    out.append(tr.rows[self.i])
                self.i += 1
            if self.i >= len(tr.t) and end > tr.duration:   # wrap
                self.loops += 1; self.i = 0
                start -= tr.duration; end -= tr.duration
                if end <= 0: break
                continue
            break
        return np.array(out, dtype=np.int64)


class ReplayBank:
    def __init__(self, pool: FlowPool, cfg: dict):
        m = pool.rules_meta.get("replay_meta")
        self.enabled = m is not None and cfg.get("replay", {}).get("enabled", True) and m.get("device_ips")
        if not self.enabled:
            return
        rcfg = cfg.get("replay", {})
        gap_cap = float(rcfg.get("gap_cap_s", 60.0))
        self.availability = str(rcfg.get("availability", "end"))
        self.cal_fraction = float(rcfg.get("calibration_fraction", 1.0 / 3.0))
        self.device_ips: list[str] = m["device_ips"]
        test = set(pool.test_idx.tolist())
        abs_t = np.asarray(m["abs_t"], dtype=np.float64)
        if self.availability == "end" and m.get("dur_s") is not None:
            abs_t = abs_t + np.asarray(m["dur_s"], dtype=np.float64)     # completed record observable at flow end
        self.abs_t = abs_t
        # benign trace per device IP (test split of the Benign chain): the first cal_fraction of the device's test
        # timeline is the calibration segment, the rest the evaluation segment (chronological, non-overlapping)
        dev = m["device"]
        self.benign: dict[int, Trace] = {}
        self.benign_cal: dict[int, Trace] = {}
        for i in range(len(self.device_ips)):
            rows = np.flatnonzero((dev == i) & (pool.y == 0) & (pool.family == BENIGN))
            rows = np.array([r for r in rows if r in test], dtype=np.int64)
            if len(rows) == 0:
                continue
            rows = rows[np.argsort(abs_t[rows], kind="stable")]
            n_cal = int(len(rows) * self.cal_fraction)
            if 0 < n_cal < len(rows):
                tr_cal, tr_eval = _build(rows[:n_cal], abs_t, gap_cap), _build(rows[n_cal:], abs_t, gap_cap)
            else:
                tr_cal = tr_eval = _build(rows, abs_t, gap_cap)
            if tr_eval is not None:
                self.benign[i] = tr_eval
                self.benign_cal[i] = tr_cal if tr_cal is not None else tr_eval
        # attack traces per family: one trace per designated attacker (test split)
        att_row = m.get("attacker_of_row")
        self.attack: dict[str, list[Trace]] = {}
        for fam in pool.families():
            fam_rows = np.flatnonzero((pool.family == fam) & (pool.y == 1))
            fam_rows = np.array([r for r in fam_rows if r in test], dtype=np.int64)
            traces = []
            if att_row is not None and len(fam_rows):
                for a in np.unique(att_row[fam_rows]):
                    if not a: continue
                    tr = _build(fam_rows[att_row[fam_rows] == a], abs_t, gap_cap)
                    if tr is not None and len(tr.rows) >= 50:
                        traces.append(tr)
            if not traces and len(fam_rows):
                traces = [_build(fam_rows, abs_t, gap_cap)]
            if traces:
                self.attack[fam] = traces
        self.devices_with_benign = sorted(self.benign)

    # ------------------------------------------------------------------
    def benign_cursor(self, dev_ip_index: int, rng: np.random.Generator, segment: str = "eval") -> Cursor | None:
        tr = (self.benign_cal if segment == "cal" else self.benign).get(dev_ip_index)
        return Cursor(tr, rng) if tr else None

    def attack_cursor(self, family: str, rng: np.random.Generator) -> Cursor | None:
        trs = self.attack.get(family)
        if not trs:
            return None
        return Cursor(trs[int(rng.integers(len(trs)))], rng)

    def summary(self) -> str:
        if not self.enabled:
            return "replay disabled"
        b = [len(t.rows) for t in self.benign.values()]
        a = {f: (len(ts), sum(len(t.rows) for t in ts)) for f, ts in self.attack.items()}
        def dens(ts):   # median flows/s and median fraction of 1-s epochs that carry >= 1 flow
            r = [len(t.rows) / max(t.duration, 1.0) for t in ts]
            occ = [min(1.0, len(np.unique(np.floor(t.t))) / max(np.ceil(t.duration), 1.0)) for t in ts]
            return f"{np.median(r):.2f}/s,occ={np.median(occ):.2f}"
        d = {f: dens(ts) for f, ts in self.attack.items()}
        bc = [t.duration for t in self.benign_cal.values()]
        return (f"replay[availability={self.availability}, calibration_fraction={self.cal_fraction:.2f}]: {len(self.benign)} devices "
                f"with benign traces (rows/device median={int(np.median(b)) if b else 0}, density {dens(list(self.benign.values()))}; "
                f"calibration segment median {np.median(bc) / 60 if bc else 0:.0f} min); attack traces {a}; attack density {d}")
