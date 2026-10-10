"""Attack campaign scheduling and cross-site partitioning.

Campaign kinds
  <traffic family>   compromised devices emit flows drawn from that family's pool
  FirmwareTamper     integrity flag flips to 0 (no traffic change)
  CredentialReplay   devices present a credential *already used* by an earlier campaign
                     at another gateway; traffic stays benign. Only a revocation that was
                     published to the cloud (and pulled by this gateway) can catch it.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class Campaign:
    gateway: int
    family: str
    onset: float
    end: float
    devices: list[int]
    credential_id: str          # credential presented by the compromised devices
    forced_holdout: bool = False

    def active(self, t: float) -> bool:
        return self.onset <= t < self.end


def _onset_window(cfg: dict) -> tuple[float, float]:
    s = cfg["scenario"]; T = cfg["topology"]["sim_duration_s"]
    lo, hi = s["onset_range_s"]
    if hi > 0.9 * T:                      # keep campaigns inside the horizon for short runs
        lo, hi = 0.10 * T, 0.80 * T
    return float(lo), float(hi)


def sample_campaigns(cfg: dict, rng: np.random.Generator, families: list[str],
                     devices_per_gateway: list[int] | None = None) -> list[Campaign]:
    s = cfg["scenario"]; top = cfg["topology"]
    lo, hi = _onset_window(cfg)
    T = top["sim_duration_s"]
    n_dev = devices_per_gateway or [top["devices_per_gateway"]] * top["n_gateways"]
    out: list[Campaign] = []

    def _new(g: int, fam: str, forced: bool = False) -> Campaign:
        onset = float(rng.uniform(lo, hi)); dur = float(rng.uniform(*s["duration_range_s"]))
        k = max(1, int(round(s["compromised_fraction"] * n_dev[g])))
        devs = rng.choice(n_dev[g], size=min(k, n_dev[g]), replace=False).tolist()
        return Campaign(g, fam, onset, min(onset + dur, T), devs, credential_id=f"cred-{len(out):03d}", forced_holdout=forced)

    # 1) cross-site: force one campaign per gateway with a family held out of its local training split
    cs = s.get("cross_site", {})
    if cs.get("enabled") and cs.get("force_holdout_campaigns", True):
        for g in range(top["n_gateways"]):
            ho = [f for f in holdout_for(cfg, g) if f in families]
            if ho:
                out.append(_new(g, str(rng.choice(ho)), forced=True))

    def _replay(g: int) -> Campaign | None:
        pref = s.get("replay_donor_families", ["DoS", "DDoS"])
        traffic = [c for c in out if c.family not in ("CredentialReplay", "FirmwareTamper") and c.gateway != g]
        seen = [c for c in traffic if c.family not in holdout_for(cfg, c.gateway)]   # donor gateway trained on that family
        donors = [c for c in seen if c.family in pref] or seen or traffic
        if not donors:
            return None
        donor = donors[int(rng.integers(len(donors)))]
        c = _new(g, "CredentialReplay")
        c.credential_id = donor.credential_id            # reuse a credential seen at another gateway
        c.onset = max(c.onset, donor.onset + 30.0)        # replay happens after the donor campaign started
        c.end = min(c.onset + float(rng.uniform(*s["duration_range_s"])), T)
        return c

    # 2) remaining campaigns
    while len(out) < s["n_campaigns"] - (1 if s.get("force_replay_campaign", True) else 0):
        g = int(rng.integers(top["n_gateways"]))
        r = rng.random()
        if r < s["credential_replay_prob"]:
            c = _replay(g)
            if c is not None:
                out.append(c); continue
            r = 1.0                                       # no donor yet -> fall through to a traffic campaign
        if r < s["credential_replay_prob"] + s["firmware_tamper_prob"] and r >= s["credential_replay_prob"]:
            out.append(_new(g, "FirmwareTamper"))
        else:
            out.append(_new(g, str(rng.choice(families))))
    # 3) guarantee one credential-replay campaign per run (it is the only way to measure the revocation path);
    #    if no suitable donor exists yet, add one flood campaign at a gateway that trained on it
    if s.get("force_replay_campaign", True):
        pref = s.get("replay_donor_families", ["DoS", "DDoS"])
        ok = [c for c in out if c.family in pref and c.family not in holdout_for(cfg, c.gateway)]
        if not ok:
            cands = [(g, f) for g in range(top["n_gateways"]) for f in pref if f in families and f not in holdout_for(cfg, g)]
            if cands:
                g, f = cands[int(rng.integers(len(cands)))]
                out.append(_new(g, f))
        for g in rng.permutation(top["n_gateways"]):
            c = _replay(int(g))
            if c is not None:
                out.append(c); break
    return sorted(out, key=lambda c: c.onset)


def holdout_for(cfg: dict, gateway: int) -> list[str]:
    cs = cfg["scenario"].get("cross_site", {})
    if not cs.get("enabled", False):
        return []
    return list(cs.get("holdout", {}).get(f"g{gateway}", []))
