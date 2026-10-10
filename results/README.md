# Result files (one row per run; columns are the metrics of paper §4.7 plus run metadata)

All files below were produced under **protocol v3** (`replay.availability: end`, `replay.calibration_fraction: 0.3333`).

| File | Experiment | Rows |
|---|---|---|
| `v3c_main.csv` | B2_rules, B3_net_only, EASA_net_score (= EASA−PH), EASA_full, EASA_reset × seeds 0–29, deployed Cloud Run service | 150 |
| `v3_main_nocloud.csv` | B0_static, B1_vnsf, EASA_minus_C × seeds 0–29 (no cloud calls) | 90 |
| `final_main_v3.csv` | the seven configurations of paper Table 5 (input of `make_figures.py`; `source` column marks the origin) | 210 |
| `final_supp_reset_v3.csv` | EASA_reset rows (supplementary, paper Table 15) | 30 |
| `v3c_outage.csv` | EASA_full with cloud calls skipped for t ∈ [1800, 2700) s × seeds 0–29, deployed service | 30 |
| `v3c_lowbattery.csv` | low-battery scenario e_d ~ U(0.10, 0.35): EASA_full, EASA_no_energy, B3_net_only × seeds 0–29, deployed service | 90 |
| `v3_main.csv` | the same configurations as `v3c_main.csv` (except EASA_reset) run against the in-process mock: per-seed metrics identical to `v3c_main.csv` | 210 |
| `v3_sensitivity.csv` | one-at-a-time sweep (w_net, beta, h, k, target FPR), EASA_full and B3_net_only × 10 seeds per point, in-process mock | 340 |
| `label_sensitivity.csv` | attacker sets and relabelled-row shares over the 27-setting grid of the labelling rule | 405 |
| `label_sensitivity_working.csv` | the alternative attacker sets of the grid applied to the working pool (train/val/test rows, replayed attacker traces) | 405 |
| `log_audit_protocol.txt` | output of `audit_protocol.py` (replay-protocol invariants, paper Appendix F) | — |
| `log_audit_v3c_main.txt` | output of `audit_recovery.py` on the seed-0 traces of `v3c_main` (paper Table 14) | — |
| `traces/<grid>/<config>_seed0.parquet` | per-epoch, per-device log of seed 0 of each configuration (input of `audit_recovery.py` and the trust-trace figure) | — |
| `protocol_v2/` | result files of the earlier protocol, kept for the record; not used by any table of the paper | — |

Column notes: `fpr_L2` is measured on never-compromised devices, `fpr_L2_all_epochs` on all benign
device-epochs; `containment_pre_restricted_rate` / `containment_new_rate` split `containment_rate` by whether the
device was already restricted at episode onset, `ttc_new_p50_s` is the TTC of newly restricted episodes;
`deferred_executed` / `deferred_cancelled` / `pending_at_end` are the outcomes of deferred step-ups; `n_hist_resets`
counts history resets (EASA_reset only); `replay_catch_rate` is unconditional, `replay_catch_rate_cond` is NaN when
no donor credential was revoked in the run; `rtt_ms_*` and `n_calls` are wall-clock round trips and counts of real
cloud calls (NaN without a cloud path); `tau_L1..L3` are the calibrated thresholds of the run;
`train_overlap_jaccard_min/max` the pairwise overlap of the gateways' training sets; `campaigns` lists the sampled
schedule (`*` = forced held-out family).
