"""Run one configuration for one seed, or the whole Table-3 grid."""
from __future__ import annotations

import json
import logging
import os
import time

import numpy as np
import pandas as pd

from .cloud import HttpCloud, make_cloud
from .data import load_pool
from .gateway import Gateway
from .metrics import frames_from_gateways, summarise
from .replay import ReplayBank
from .scenario import holdout_for, sample_campaigns

log = logging.getLogger(__name__)


def run_once(cfg: dict, seed: int, pool=None, save_traces: bool = False, trace_tag: str = "") -> dict:
    rng = np.random.default_rng(seed)
    if pool is None:
        pool = load_pool(cfg, rng)
    cloud = make_cloud(cfg)
    if isinstance(cloud, HttpCloud):
        if not cloud.health():
            raise RuntimeError("cloud service unreachable -- check cloud.base_url and EASA_API_KEY")
        cloud.reset()
    top = cfg["topology"]
    replay = ReplayBank(pool, cfg)
    if replay.enabled:
        # distribute the real device IPs (those with a benign trace) round-robin over gateways
        ids = replay.devices_with_benign
        per_gw = [ids[g::top["n_gateways"]] for g in range(top["n_gateways"])]
        cap = top.get("devices_per_gateway")
        if isinstance(cap, int):
            per_gw = [p[:cap] for p in per_gw]
        # load scaling (revision r1, R2): each device trace is instantiated `device_multiplier` times per gateway, every
        # instance replaying the same trace from an independent random phase (n devices -> k*n devices, same traffic mix)
        mult = int(top.get("device_multiplier", 1))
        if mult > 1:
            per_gw = [p * mult for p in per_gw]
        log.info("%s; devices per gateway = %s", replay.summary(), [len(p) for p in per_gw])
    else:
        per_gw = [None] * top["n_gateways"]
    device_owner = {int(d): g for g in range(top["n_gateways"]) for d in (per_gw[g] or [])}
    # federation-wide device holdout (revision r1, editor point 2): every k-th replayed device (k = 1/fraction, by
    # replay index, deterministic across seeds) has its benign rows removed from every gateway's training set.
    gh_frac = float(top.get("global_holdout_devices_fraction", 0.0) or 0.0)
    gh: set[int] = set()
    if replay.enabled and gh_frac > 0:
        k = max(1, int(round(1.0 / gh_frac)))
        ng = top["n_gateways"]
        # every k-th round-robin "round" (so the held-out devices are spread over all gateways, not one gateway)
        gh = {int(d) for i, d in enumerate(replay.devices_with_benign) if (i // ng) % k == k - 1}
        log.info("global device holdout: %d of %d devices excluded from all training: %s", len(gh), len(replay.devices_with_benign),
                 [replay.device_ips[d] for d in sorted(gh)])
    top["_global_holdout_devices"] = sorted(gh)
    gateways = [Gateway(g, cfg, pool, cloud, np.random.default_rng(seed * 100 + g), holdout_for(cfg, g), seed,
                        replay=replay, device_ip_indices=per_gw[g], device_owner=device_owner)
                for g in range(top["n_gateways"])]
    # ---- initial training. With a cloud: standard FedAvg (common init, R rounds x E local epochs, average
    #      between rounds). Without a cloud (EASA-C, B0-B2): the same total number of local epochs.
    det = cfg["detector"]
    federated = cloud.sync_model_enabled and gateways[0].detector.federatable
    if federated:
        rounds, local_ep = int(det.get("fed_rounds", 5)), int(det.get("fed_local_epochs", 3))
        for r in range(rounds):
            for g in gateways:
                g.train_local(epochs=local_ep)
                cloud.push_stats(g.name, g.detector.get_vector(), g.detector.n_samples_seen(), g.policy_version)
            vec, ver = cloud.pull_model()
            if vec is not None:
                for g in gateways:
                    g.detector.set_vector(vec); g.model_version = ver
        log.info("federated warm-up: %d rounds x %d local epochs, global model v%d", rounds, local_ep, gateways[0].model_version)
    else:
        for g in gateways:
            g.train_local()
    for g in gateways:
        log.info("%s val detections@0.5 (Benign = FPR, * = holdout): %s", g.name, g.val_report())
    # ---- threshold calibration: a benign-only pass fixes the operating point of every configuration at the
    #      same epoch-level false-positive rate (IDS practice: compare recall/TTC/overhead at equal FPR)
    cal = cfg["policy"].get("calibrate", {})
    tau = {k: float(v) for k, v in cfg["policy"]["tau_enter"].items()}
    n_outliers = 0; res_cal = {}
    if cal.get("enabled", False) and not gateways[0].policy.disabled and not gateways[0].trust.disabled:
        dt = top["epoch_s"]
        saved = [(g.cloud.sync_model_enabled, g.cloud.revocation_enabled, g.cloud.audit_enabled) for g in gateways]
        for g in gateways:   # no cloud traffic during calibration
            g.cloud.sync_model_enabled = g.cloud.revocation_enabled = g.cloud.audit_enabled = False

        # Protocol v4 (revision r1): chronic outliers. A device that sits at >= L2 for more than `exclude_chronic` of
        # the benign pass under the current thresholds is a persistent detector false positive (its benign traffic is
        # scored as attack-like in every seed; Section 5.7). Such devices are excluded from the FPR statistic that the
        # bisection targets and from the quantiles that set tau_L1 / tau_L3 -- otherwise one such device (1/65 of the
        # device-epochs) consumes most of a 2 % budget and forces the fleet's thresholds down -- and are reported as
        # n_calibration_outliers (they stay in the evaluation and in every evaluated metric; operationally they are the
        # operator-review queue). exclude_chronic = 0 reproduces protocol v3.
        chronic = float(cal.get("exclude_chronic", 0.0))

        def benign_pass(tau_: dict | None):
            for g in gateways:
                g.reset_state(segment="cal")      # protocol v3: chronologically earlier, non-overlapping segment
                if tau_ is not None:
                    g.policy.tau = {1: tau_["L1"], 2: tau_["L2"], 3: tau_["L3"]}
                    g.policy.delta = max(tau_["L1"] - tau_["L2"], 1e-3)   # hysteresis width = L1-L2 spread
            t = 0.0
            while t < float(cal.get("duration_s", 1800)):
                for g in gateways: g.step(t, [])
                t += dt
            T_, lv_, dev_ = [], [], []
            for g in gateways:
                for d in g.devices:
                    for row in d.log_rows:
                        T_.append(row[7]); lv_.append(row[8]); dev_.append(d.did)
            return np.array(T_), np.array(lv_), np.array(dev_)

        def chronic_mask(lv_, dev_):
            """True for epochs of devices restricted (>= L2) for more than `chronic` of the pass."""
            if chronic <= 0: return np.zeros(len(lv_), dtype=bool)
            s = pd.Series(lv_ >= 2).groupby(pd.Series(dev_)).mean()
            bad = set(s[s > chronic].index)
            return np.array([d_ in bad for d_ in dev_])

        # pass 1: quantiles of benign T give the first guess; then bisect tau_L2 so that the *realised*
        # fraction of benign device-epochs at >= L2 (hysteresis included) matches target_fpr
        Tb, lv0, dev0 = benign_pass(None)
        target = float(cal.get("target_fpr", 0.02))
        q1, q3 = float(cal.get("l1_quantile", 0.10)), float(cal.get("l3_quantile", 0.005))
        # pass 1 runs with the uncalibrated tau, so the first guess uses every epoch; chronic outliers are identified
        # under the calibrated tau on every later pass and the quantiles are then taken over the remaining devices
        keep = np.ones(len(Tb), bool)
        tau = {"L1": float(np.quantile(Tb, q1)), "L2": float(np.quantile(Tb, target)), "L3": float(np.quantile(Tb, q3))}
        lo, hi = float(np.quantile(Tb, 0.0005)), tau["L1"] - 1e-3
        fpr = None; n_outliers = 0
        for _ in range(int(cal.get("max_passes", 6))):
            tau["L2"] = float(np.clip(tau["L2"], lo, hi))
            if str(cal.get("l3_rule", "spread")) == "quantile":
                # protocol v4: tau_L3 is the q3 quantile of benign T alone (capped just below tau_L2). The v3 rule
                # ("one L1-L2 spread below L2") couples tau_L3 to the spread, which differs between configurations
                # (0.12 for the composite, 0.17-0.30 for net-only scores) and bound in 14/30 seeds of the submitted
                # run and 26/30 seeds once attacker hosts were dropped, where it pushed tau_L3 of the net-only
                # configurations towards 0 and made L3 (and hence revocation) unreachable for them.
                tau["L3"] = max(0.0, min(float(np.quantile(Tb[keep], q3)), tau["L2"] - 1e-3))
            else:
                tau["L3"] = max(0.0, min(float(np.quantile(Tb[keep], q3)), tau["L2"] - (tau["L1"] - tau["L2"])))   # L3 one spread below L2 (>= 0)
            _, lv, dev_ = benign_pass(tau)
            cm = chronic_mask(lv, dev_)
            if chronic > 0 and cm.any() and (~cm).mean() >= 0.5 and len(set(dev_[cm])) != n_outliers:
                keep = ~cm                                   # same row order as pass 1 (gateways -> devices -> epochs)
                tau["L1"] = float(np.quantile(Tb[keep], q1)); hi = min(hi, tau["L1"] - 1e-3)
            n_outliers = len(set(dev_[cm]))
            fpr = float((lv[~cm] >= 2).mean()) if (~cm).any() else float((lv >= 2).mean())
            if abs(fpr - target) <= 0.25 * target: break
            if fpr > target: hi = tau["L2"]
            else: lo = tau["L2"]
            tau["L2"] = 0.5 * (lo + hi)
        if chronic > 0:
            log.info("calibration: %d chronic-outlier device(s) excluded from the FPR statistic (restricted > %.0f%% of the benign pass)", n_outliers, 100 * chronic)
        # Protocol v4 (revision r1): per-device thresholds. Every device d gets tau_L2^d = q_d(p), tau_L1^d = q_d(q1),
        # tau_L3^d = min(q_d(q3), tau_L2^d - (tau_L1^d - tau_L2^d)) from ITS OWN benign calibration segment, with one
        # quantile level p shared by all devices and bisected so that the realised fleet FPR (hysteresis included)
        # meets the target: the operating point stays common to every configuration, while a device whose benign
        # traffic the detector scores low is compared against its own baseline instead of consuming the fleet's budget.
        if bool(cal.get("per_device", False)):
            Tb0, _, dev0_ = benign_pass(None)
            by_dev = {d_: Tb0[dev0_ == d_] for d_ in np.unique(dev0_)}

            def tau_for(p_):
                out_ = {}
                for d_, T_ in by_dev.items():
                    l1, l2, l3 = float(np.quantile(T_, q1)), float(np.quantile(T_, p_)), float(np.quantile(T_, q3))
                    l2 = min(l2, l1 - 1e-3); l3 = max(0.0, min(l3, l2 - (l1 - l2)))
                    out_[d_] = ({1: l1, 2: l2, 3: l3}, max(l1 - l2, 1e-3))
                return out_

            def pass_with(p_):
                tbd = tau_for(p_)
                for g in gateways:
                    g.policy.tau_by_device = tbd
                _, lv_, _ = benign_pass({"L1": 1.0, "L2": 0.0, "L3": 0.0})   # fleet tau irrelevant: every device overridden
                return float((lv_ >= 2).mean()), tbd

            lo_p, hi_p, p_cal = 0.0005, min(0.5 * q1, 0.08), target
            fpr, tbd = pass_with(p_cal)
            for _ in range(int(cal.get("max_passes", 6))):
                if abs(fpr - target) <= 0.25 * target: break
                if fpr > target: hi_p = p_cal
                else: lo_p = p_cal
                p_cal = 0.5 * (lo_p + hi_p)
                fpr, tbd = pass_with(p_cal)
            tau = {"L1": float(np.mean([v[0][1] for v in tbd.values()])), "L2": float(np.mean([v[0][2] for v in tbd.values()])),
                   "L3": float(np.mean([v[0][3] for v in tbd.values()]))}     # fleet means, reported
            for g in gateways:
                g.policy.tau_by_device = tbd
            res_cal = {"cal_quantile_level": p_cal, "tau_L2_device_min": float(min(v[0][2] for v in tbd.values())),
                       "tau_L2_device_max": float(max(v[0][2] for v in tbd.values()))}
            log.info("per-device calibration: quantile level p=%.4f -> fleet FPR %.3f (target %.3f); tau_L2 per device %.3f..%.3f (mean %.3f)",
                     p_cal, fpr, target, res_cal["tau_L2_device_min"], res_cal["tau_L2_device_max"], tau["L2"])
        else:
            res_cal = {}
        for g, (a, b, c_) in zip(gateways, saved):
            g.policy.tau = {1: tau["L1"], 2: tau["L2"], 3: tau["L3"]}
            g.policy.delta = max(tau["L1"] - tau["L2"], 1e-3)
            g.cloud.sync_model_enabled, g.cloud.revocation_enabled, g.cloud.audit_enabled = a, b, c_
            g.reset_state(segment="eval")
        log.info("calibrated thresholds (benign pass, %d device-epochs): tau_L1=%.3f tau_L2=%.3f tau_L3=%.3f delta=%.3f -> benign FPR %.3f (target %.3f)",
                 len(Tb), tau["L1"], tau["L2"], tau["L3"], gateways[0].policy.delta, fpr, target)
    campaigns = sample_campaigns(cfg, rng, pool.families(), [len(g.devices) for g in gateways])
    log.info("campaigns: %s", " ".join(f"{c.family}@g{c.gateway}[{int(c.onset)}-{int(c.end)}]{'*' if c.forced_holdout else ''}" for c in campaigns))
    outage = cfg["cloud"].get("outage", {})
    t, dt, T_end = 0.0, top["epoch_s"], top["sim_duration_s"]
    wall0 = time.perf_counter()
    while t < T_end:
        in_outage = outage.get("enabled") and outage["start_s"] <= t < outage["start_s"] + outage["duration_s"]
        for g in gateways:
            if in_outage:   # gateway keeps scoring/enforcing with last synced state; sync calls are skipped
                saved = (g.cloud.sync_model_enabled, g.cloud.revocation_enabled, g.cloud.audit_enabled)
                g.cloud.sync_model_enabled = g.cloud.revocation_enabled = g.cloud.audit_enabled = False
                g.step(t, campaigns)
                g.cloud.sync_model_enabled, g.cloud.revocation_enabled, g.cloud.audit_enabled = saved
            else:
                g.step(t, campaigns)
        t += dt
    wall = time.perf_counter() - wall0
    n_epochs_run = int(round(T_end / dt))
    df = frames_from_gateways(gateways)
    res = summarise(df, dt, T_end)
    # revocation path diagnostics: was the donor credential of each replay campaign actually revoked (L3 elsewhere)?
    revoked_all = set().union(*[g.revoked for g in gateways])
    replays = [c for c in campaigns if c.family == "CredentialReplay"]
    donor_revoked = [c.credential_id in revoked_all for c in replays]
    res["n_revocations"] = len(revoked_all)
    res.update({"tau_L1": tau["L1"], "tau_L2": tau["L2"], "tau_L3": tau["L3"]})
    res["campaigns"] = " ".join(f"{c.family}@g{c.gateway}{'*' if c.forced_holdout else ''}" for c in campaigns)
    # energy-aware step-up bookkeeping: deferred = executed later + cancelled (device relaxed) + still pending at the end
    ps_all = [d.policy for g in gateways for d in g.devices]
    res["deferred_executed"] = int(sum(p.n_deferred_executed for p in ps_all))
    res["deferred_cancelled"] = int(sum(p.n_deferred_cancelled for p in ps_all))
    res["pending_at_end"] = int(sum(p.pending_stepup for p in ps_all))
    res["n_hist_resets"] = int(sum(d.trust.n_hist_resets for g in gateways for d in g.devices))
    res["n_calibration_outliers"] = int(n_outliers) if (cal.get("enabled", False) and not gateways[0].policy.disabled and not gateways[0].trust.disabled) else 0
    res.update(res_cal)
    res["n_clean_releases"] = int(sum(p.n_clean_releases for p in ps_all))
    res["n_devices"] = int(sum(len(g.devices) for g in gateways))
    res["n_devices_excluded_short_trace"] = len(getattr(replay, "excluded_short", []) or [])
    res["training_partition"] = str(top.get("training_partition", "shared"))
    res["global_holdout_devices_fraction"] = float(top.get("global_holdout_devices_fraction", 0.0) or 0.0)
    res["global_holdout_device_ids"] = ";".join(f"g{device_owner[d]}-d{(per_gw[device_owner[d]] or []).index(d):03d}" for d in sorted(gh)) if gh else ""
    res["device_multiplier"] = int(top.get("device_multiplier", 1))
    # training-data overlap between gateways (shared: the pool's training split minus the held-out family; disjoint: 0)
    tr_sets = [set(g.train_rows().tolist()) for g in gateways]
    res["train_rows_per_gateway"] = " ".join(str(len(s_)) for s_ in tr_sets)
    if len(tr_sets) > 1:
        ov = [len(tr_sets[i] & tr_sets[j]) / max(1, len(tr_sets[i] | tr_sets[j])) for i in range(len(tr_sets)) for j in range(i + 1, len(tr_sets))]
        res["train_overlap_jaccard_min"] = float(min(ov)); res["train_overlap_jaccard_max"] = float(max(ov))
    res["replay_availability"] = cfg.get("replay", {}).get("availability", "end")
    res["calibration_fraction"] = float(cfg.get("replay", {}).get("calibration_fraction", 1.0 / 3.0))
    res["protocol_hash"] = protocol_hash(cfg)
    res["n_replay_campaigns"] = len(replays)
    res["replay_donor_revoked_rate"] = float(np.mean(donor_revoked)) if replays else float("nan")
    res["replay_catch_rate_cond"] = res["replay_catch_rate"] if any(donor_revoked) else float("nan")
    res.update({"seed": seed, "config": cfg["experiment"]["config_name"], "wall_s": wall,
                "wall_ms_per_epoch": 1000.0 * wall / max(1, n_epochs_run),
                "n_campaigns": len(campaigns), "dup_ratio": pool.rules_meta.get("dup_ratio", 0.0),
                "detector": cfg["detector"]["kind"], "cloud_mode": cfg["cloud"]["mode"],
                "cloud_transport": "http" if isinstance(cloud, HttpCloud) else ("none" if cfg["cloud"]["mode"] == "none" else "local")})
    if isinstance(cloud, HttpCloud):
        res.update(cloud.rtt_summary())
        if cloud.n_errors:
            log.warning("%d cloud calls failed in this run (gateways continued on last synced state)", cloud.n_errors)
    if save_traces:
        out = os.path.join(cfg["experiment"]["out_dir"], "traces", trace_tag) if trace_tag else os.path.join(cfg["experiment"]["out_dir"], "traces")
        os.makedirs(out, exist_ok=True)
        base = os.path.join(out, f"{cfg['experiment']['config_name']}_seed{seed}")
        try:
            df.to_parquet(base + ".parquet", index=False)
        except ImportError:   # pyarrow missing -> compressed CSV
            df.to_csv(base + ".csv.gz", index=False)
    return res


def protocol_hash(cfg: dict) -> str:
    """Short hash of the config sections that define the replay protocol (data split, labelling, replay, calibration).
    Written into every result row; run_grid refuses to resume a CSV whose rows carry a different hash."""
    import hashlib, json
    keys = {k: cfg.get(k) for k in ("data", "replay", "calibration", "sim")}
    top = cfg.get("topology", {})
    keys["topology_r1"] = {k: top.get(k) for k in ("training_partition", "device_multiplier", "global_holdout_devices_fraction") if top.get(k) not in (None, "shared", 1, 0, 0.0)}
    calx = cfg.get("policy", {}).get("calibrate", {}).get("exclude_chronic", 0)
    if calx: keys["calibration_r1"] = {"exclude_chronic": calx}
    if cfg.get("policy", {}).get("calibrate", {}).get("per_device", False): keys["calibration_v4"] = "per_device"
    if cfg.get("policy", {}).get("calibrate", {}).get("l3_rule", "spread") != "spread": keys["calibration_l3"] = cfg["policy"]["calibrate"]["l3_rule"]
    return hashlib.sha1(json.dumps(keys, sort_keys=True, default=str).encode()).hexdigest()[:10]


def run_grid(cfg_full: dict, config_names: list[str], seeds: list[int], out_csv: str, pool=None,
             resume: bool = True, save_all_traces: bool = False) -> pd.DataFrame:
    """Runs the grid; with resume=True (default) (config, seed) pairs already present in out_csv are skipped,
    so an interrupted grid is continued by re-running the same command."""
    from .config import materialise
    rows, done = [], set()
    if resume and os.path.exists(out_csv):
        try:
            prev = pd.read_csv(out_csv)
            if "protocol_hash" in prev.columns and (prev["protocol_hash"].astype(str) != protocol_hash(cfg)).any():
                raise SystemExit(f"{out_csv} holds runs of a different protocol (hash {prev['protocol_hash'].iloc[0]} vs "
                                 f"{protocol_hash(cfg)}); use --fresh or another --out")
            if "protocol_hash" not in prev.columns:
                raise SystemExit(f"{out_csv} predates protocol hashing; use --fresh or another --out")
            rows = prev.to_dict("records"); done = set(zip(prev["config"], prev["seed"]))
            log.info("resuming %s: %d runs already done", out_csv, len(done))
        except Exception as e:  # noqa: BLE001
            log.warning("could not read %s for resume (%s) -- starting fresh", out_csv, e)
    for name in config_names:
        cfg = materialise(cfg_full, name)
        for s in seeds:
            if (name, s) in done:
                continue
            log.info("=== %s seed=%d", name, s)
            tag = os.path.splitext(os.path.basename(out_csv))[0]          # traces/<csv name>/<config>_seed<k>
            r = run_once(cfg, s, pool=pool, save_traces=(save_all_traces or s == seeds[0]), trace_tag=tag)
            rows.append(r)
            pd.DataFrame(rows).to_csv(out_csv, index=False)   # incremental save
            log.info(json.dumps({k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()}))
    return pd.DataFrame(rows)
