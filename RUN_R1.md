# Revision round 1 — experiment runs (Sensors, Nov 2026)

All runs use the in-process cloud mock (`cloud.transport=local`), which is bit-identical to the deployed service
(paper §5.8), so nothing needs to be redeployed. Run from `easa_sim/` in PowerShell. Every command resumes if
interrupted (re-run the same line). Expected wall time per run ≈ 60 s on the RTX 5080 machine; estimates below
assume that. Run E3 and E4 first (fast, answer the editor directly), then E1, E2, E5, then the TON_IoT replication.

Before anything: copy the files of `revision_r1_code.zip` over your local clone (they only add options; all existing
commands and results are unchanged) and run the smoke test:

```powershell
python scripts/run_experiments.py --set data.source=synthetic --set cloud.mode=local --set topology.devices_per_gateway=20 --set topology.sim_duration_s=600 --seeds 1 --configs EASA_full EASA_net_binary EASA_release --out results/_smoke.csv --fresh
```

## E3 — graded vs. binary enforcement, same detector, same cloud (editor 3, R3)   ~1 h
`EASA_net_binary` = EASA_net_score (EASA−PH) with the binary L0↔L3 policy. The pair isolates the graded controller.

```powershell
python scripts/run_experiments.py --set cloud.transport=local --configs EASA_net_binary --out results/r1_binary.csv
```
Send: `results/r1_binary.csv`.

## E4 — recovery audit over all 30 seeds + bounded dwell (editor 4, R4)   ~2.5 h
`EASA_release` adds the bounded-dwell rule (an L2 device whose network score alone sits at the L0 level for 12
consecutive epochs = 120 s is released to L1 and the release is logged); `EASA_reset_release` combines it with the
history reset. `--save-all-traces` writes the per-epoch trace of every seed (≈ 2 MB each) for the audit.

```powershell
python scripts/run_experiments.py --set cloud.transport=local --save-all-traces --configs EASA_full EASA_net_score EASA_reset EASA_release EASA_reset_release --out results/r1_recovery.csv
python scripts/audit_recovery.py results/traces/r1_recovery --out results/r1_audit_all_seeds.csv
```
Send: `results/r1_recovery.csv`, `results/r1_audit_all_seeds.csv`, `results/r1_audit_all_seeds_agg.csv`
(the `traces/r1_recovery/` folder stays on your machine; the EASA_full seed-0 trace there is also the new Fig. 3 input).

## E1 — robustness to the labelling rule (editor 1, R3, R4)   ~6 h (4 rules × 3 configs × 30 seeds)
The attacker sets are recomputed for each rule (one pass over the attack files, ~10 min each, cached as
`data/IoT-DIAD-2024/flow/iotdiad_attackers_ms…json`; the default cache is untouched).

```powershell
python scripts/run_experiments.py --set cloud.transport=local --set data.iotdiad_min_share=0.03 --configs B3_net_only EASA_net_score EASA_full --out results/r1_label_ms3_cap8.csv
python scripts/run_experiments.py --set cloud.transport=local --set data.iotdiad_max_attackers=6 --configs B3_net_only EASA_net_score EASA_full --out results/r1_label_ms5_cap6.csv
python scripts/run_experiments.py --set cloud.transport=local --set data.iotdiad_max_attackers=12 --configs B3_net_only EASA_net_score EASA_full --out results/r1_label_ms5_cap12.csv
python scripts/run_experiments.py --set cloud.transport=local --set data.iotdiad_min_share=0.10 --configs B3_net_only EASA_net_score EASA_full --out results/r1_label_ms10_cap8.csv
```
Send: the four `results/r1_label_*.csv` and the four new `iotdiad_attackers_ms*.json` caches.

## E2 — disjoint gateway training sets (editor 2, R3)   ~3 h (2 partitions × 3 configs × 30 seeds)
`disjoint`: no training row shared between gateways (attack captures cut into contiguous time blocks, each gateway
keeps the earlier traffic of its own devices). `disjoint_device`: in addition, a gateway trains on no row of any
device it evaluates.

```powershell
python scripts/run_experiments.py --set cloud.transport=local --set topology.training_partition=disjoint --configs B3_net_only EASA_net_score EASA_full --out results/r1_partition_disjoint.csv
python scripts/run_experiments.py --set cloud.transport=local --set topology.training_partition=disjoint_device --configs B3_net_only EASA_net_score EASA_full --out results/r1_partition_disjoint_device.csv
```
Send: both CSVs. (Check in the log that `train_overlap_jaccard_max` is 0.0 for these runs.)

## E5 — load and resource heterogeneity (R2)   ~2.5 h (10 seeds per point)
Load: every device trace instantiated 2× / 3× per gateway (130 / 195 devices). Heterogeneity: battery-dominated
fleet (70 % sensors) with a wide initial-energy spread. Each run also records `wall_ms_per_epoch`.

```powershell
python scripts/run_experiments.py --set cloud.transport=local --set topology.device_multiplier=2 --seeds 10 --configs B3_net_only EASA_full --out results/r1_load_x2.csv
python scripts/run_experiments.py --set cloud.transport=local --set topology.device_multiplier=3 --seeds 10 --configs B3_net_only EASA_full --out results/r1_load_x3.csv
python scripts/run_experiments.py --set cloud.transport=local --set posture.classes.sensor.share=0.70 --set posture.classes.camera.share=0.10 --set posture.classes.hub.share=0.10 --set posture.classes.appliance.share=0.10 --set "posture.init_energy_range=[0.10, 1.00]" --seeds 10 --configs B3_net_only EASA_full --out results/r1_hetero.csv
```
Send: the three CSVs.

## T — reduced replication on TON_IoT with ground-truth labels (editor 1 "independently labelled dataset")
1. Data: the timestamped network files `Processed_datasets/Processed_Network_dataset/Network_dataset_k.csv` of TON_IoT
   (UNSW Canberra Cyber, https://research.unsw.edu.au/projects/toniot-datasets). `Train_Test_Network.csv` carries no
   `ts` column and cannot be replayed. Nine of the 23 files are used (every attack type + the large normal blocks):
   k = 1, 8, 11, 12, 17, 18, 20, 22, 23 -> copied to `easa_sim/data/TON_IoT/Network_dataset_<k>.csv` (paths in `config/v4_toniot.yaml`)
   (the other files may stay in the folder; only those nine are read). Every (file, attack type) block is capped at
   its first 150,000 rows in time; normal rows are not capped (~3.0 M rows, see `config/v4_toniot.yaml`).
2. Dry run per file (optional, already done): `python scripts/inspect_toniot.py data/TON_IoT/Network_dataset_1.csv`.
3. Window T (`run_v4\window_T.ps1`, ~3-4 h): device list, protocol audit, then the grid (B3, EASA-PH, EASA x 30 seeds)
   once under the dataset's true labels and once under the paper's dominant-source rule, both with the v4 label hygiene
   (normal rows of designated attacker hosts dropped), tau_L3 quantile rule and minimum-trace rule.
```powershell
.\run_v4\window_T.ps1
```
Send: `results\v4\v4_toniot_truth.csv`, `results\v4\v4_toniot_rule.csv`, `results\v4\toniot_label_check.json`,
`results\v4\toniot_devices.csv`, `results\v4\log_audit_protocol_toniot.txt`, `results\v4\log_T.txt`.

## Environment details for the paper (R4)
Please also send the output of:
```powershell
python -c "import sys, numpy, pandas, sklearn, scipy, torch, xgboost; print(sys.version); print('numpy', numpy.__version__, 'pandas', pandas.__version__, 'sklearn', sklearn.__version__, 'scipy', scipy.__version__, 'torch', torch.__version__, torch.version.cuda, 'xgboost', xgboost.__version__)"
```
and the CPU model / RAM / GPU / OS of the machine (Settings → System → About), so that §4 can state the execution
environment exactly.

## Revision round 1, internal review of the revised draft (2026-11-12)
Apply the patch, then run the two windows from `easa_sim` (venv active; `Set-ExecutionPolicy -Scope Process Bypass`):
```powershell
.\run_v4\window_T.ps1     # TON_IoT rerun with availability = ts + duration (no 120 s cap) + non-circular label check + audits, ~2.5 h
.\run_v4\window_R.ps1     # hygiene manifest, B3_local (model-sharing contrast), federation-wide device holdout, ~3 h
```
Send: `results\v4\hygiene_manifest.csv`, `toniot_label_matrix.json`, `toniot_label_check.json`, `toniot_devices.csv`,
`log_audit_protocol_toniot.txt`, `v4_toniot_truth.csv`, `v4_toniot_rule.csv`, `toniot_device_scores_*.csv`, `toniot_audit*.csv`,
`v4_b3local.csv`, `v4_partition_disjoint_b3local.csv`, `v4_holdout.csv`, `v4_holdout_split.csv`, `log_T.txt`, `log_R.txt`.

## Optional items (window O) and the packet-identity check
`.\run_v4\window_O.ps1` writes `results\v4\devices_v4.csv` (56 replayed devices) and tries to list the dataset portal
(`download_iotdiad.py --dry-run --root .`; the portal answers 403 until its download form has been submitted in a browser).
The identity check of the seven designated benign-chain addresses was made against the packet-based release through the
portal (first 100 MB per file, no download); `results\v4\iotdiad_packet_identity.json` holds the counts and
`scripts\packet_identity_check.py` reproduces them from downloaded packet CSVs.
