#!/usr/bin/env python3
"""Replace every \\caption{...} that precedes a known \\label{...} with a one-line caption (paper style: the caption
states what the table or figure shows; definitions live in the text).

  python scripts/shorten_captions.py figures/*.tex ../sec_*.tex
"""
import re
import sys

CAPTIONS = {
    # related / proposed / setup
    "tab:related": "Closest designs on the four axes measured in this paper, summarised from the cited papers.",
    "tab:levels": "Security levels enforced by the PEP (actions are cumulative from $L_3$ down to $L_0$).",
    "tab:transitions": "Transition rules of the PDP, one row per case.",
    "tab:api": "EASA API primitives and their implementation status.",
    "tab:ablation": "Baselines and ablations expressed as EASA configurations.",
    "tab:data": "Working dataset after labelling, sampling and splitting.",
    "tab:setup": "Emulation and policy parameters.",
    # results
    "tab:results": "Main results over 30 seeds (mean $\\pm$ sample std).",
    "tab:benign": "Benign-side cost over 30 seeds (mean $\\pm$ std).",
    "tab:episodes": "Restriction activation per attack episode, split by whether the device was already restricted at onset (mean $\\pm$ std).",
    "tab:family": "Recall at the $L_2$ boundary per attack family (runs in which the family occurs in parentheses).",
    "tab:replay": "Credential-replay denominators and catch rates per configuration (30 runs).",
    "tab:lowbattery": "Low-battery scenario ($e_d\\sim U(0.10,0.35)$ at $t=0$, 30 seeds): the energy-aware selector isolated by EASA with and without it.",
    "tab:audit": "Trajectory audit of seed 0: benign restriction episodes, their recovery and the post-attack restricted time of compromised devices.",
    "tab:reset": "Supplementary design revision: EASA with history reset versus EASA on the same 30 seeds (unadjusted $p$).",
    "tab:rtt": "Real cloud calls per run and round-trip times (Cloud Run, Seoul region).",
    "tab:thresholds": "Calibrated entry thresholds (mean $\\pm$ std over seeds).",
    # appendix
    "tab:attackers": "Designated attacker addresses per attack type in CIC IoT-DIAD 2024 (last octet in 192.168.137.0/24).",
    "tab:sensitivity": "Sensitivity sweep: one parameter varied at a time around the defaults (10 seeds per point, in-process cloud mock).",
    "tab:paired": "Paired differences versus EASA, detection metrics (Holm-corrected over six comparisons per metric).",
    "tab:paired-cost": "Paired differences versus EASA, benign-side cost metrics (EASA is better when lower).",
    "tab:labelsens": "Sensitivity of the labelling rule to its thresholds on the raw captures: Jaccard overlap with the default attacker set and share of rows relabelled.",
    "tab:labelsens-working": "Sensitivity of the labelling rule on the working data and the replayed attacker traces.",
    "tab:protocol": "Implementation audit of the replay protocol on the working pool.",
    # figures
    "fig:easa-arch": "EASA architecture: the gateway closes the sense--score--decide--enforce loop locally and the cloud holds only cross-gateway state.",
    "fig:metrics": "Six headline metrics over 30 seeds (dashed line: target false-positive rate; EASA hatched).",
    "fig:trace": "Trust trajectories (EASA, seed 0): a compromised device quarantined at $L_3$ (top), a benign device never restricted (middle) and a benign device locked at $L_2$ by its decayed history term (bottom).",
    "fig:family": "Recall at the $L_2$ boundary per attack family (B0 and FirmwareTamper omitted).",
    "fig:cross-site": "In-distribution versus cross-site recall: only the configurations with a cloud model path retain recall on families a gateway never trained on.",
    "fig:outage": "EASA with the cloud reachable versus a 900\\,s outage (30 seeds each): only the revocation-dependent metrics move.",
    "fig:sensitivity": "EASA under one-at-a-time parameter variation (mean $\\pm$ std over 10 seeds, in-process cloud mock).",
}

PAT = re.compile(r"\\caption\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}(\s*)\\label\{([^}]+)\}", re.S)


def shorten(text: str) -> tuple[str, int]:
    n = 0

    def rep(m):
        nonlocal n
        key = m.group(3)
        if key in CAPTIONS:
            n += 1
            return "\\caption{" + CAPTIONS[key] + "}" + m.group(2) + "\\label{" + key + "}"
        return m.group(0)
    return PAT.sub(rep, text), n


def main():
    total = 0
    for p in sys.argv[1:]:
        s = open(p).read(); t, n = shorten(s)
        if n:
            open(p, "w").write(t); total += n; print(f"{p}: {n} caption(s)")
    print("captions shortened:", total)


if __name__ == "__main__":
    main()
