"""Trust Scoring Engine (Section 3.3): Eqs. (1)-(4)."""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np


@dataclass
class TrustState:
    T: float = 1.0
    S_net: float = 1.0
    S_pos: float = 1.0
    S_hist: float = 1.0
    clean_streak: int = 0          # consecutive restricted epochs whose network score alone would place the device at L0
    n_hist_resets: int = 0
    history: list = field(default_factory=list)


class TrustEngine:
    def __init__(self, cfg: dict):
        t = cfg["trust"]
        w = np.array([t["w_net"], t["w_pos"], t["w_hist"]], dtype=float)
        self.disabled = w.sum() == 0          # B0: no trust computation
        self.w = w / w.sum() if not self.disabled else w
        self.beta = t["beta"]
        self.lam = t["lambda_hist"]
        self.cfg = t

    def update(self, st: TrustState, attack_prob: float, s_pos: float, prev_level: int,
               tau_L1: float | None = None, reset_after: int = 0) -> float:
        """One epoch. attack_prob is f_theta(x) for the current window; prev_level is l_d(t-1).
        Recovery rule (policy.history_reset_epochs = reset_after > 0, review round 2 / R7): while the device is
        restricted (>= L2), if the network score alone has been at the L0 level (S_net >= tau_L1) for reset_after
        consecutive epochs, the decision-history term is reset to 1 so that a benign device cannot be held at L2 by
        its own past decisions. reset_after = 0 disables the rule (protocol v3 default)."""
        if self.disabled:
            st.T = 1.0
            return st.T
        st.S_net = 1.0 - float(attack_prob)                                   # Eq. (1)
        st.S_pos = float(s_pos)                                                # Eq. (2)
        st.S_hist = self.lam * st.S_hist + (1 - self.lam) * (1.0 if prev_level <= 1 else 0.0)   # Eq. (3)
        if reset_after > 0 and tau_L1 is not None:
            if prev_level >= 2 and st.S_net >= tau_L1:
                st.clean_streak += 1
                if st.clean_streak >= reset_after:
                    st.S_hist = 1.0; st.n_hist_resets += 1; st.clean_streak = 0
            else:
                st.clean_streak = 0
        T_tilde = self.w[0] * st.S_net + self.w[1] * st.S_pos + self.w[2] * st.S_hist
        st.T = self.beta * st.T + (1 - self.beta) * T_tilde                    # Eq. (4)
        return st.T
