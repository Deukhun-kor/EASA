# Result files of the revision (protocol v4)

All files in this folder were produced under **protocol v4** (`easa_sim/config/v4.yaml`, which extends
`default.yaml`): Benign-chain rows of designated attacker hosts removed (7 of 65 replayed addresses), τ_L3 by the
0.5 % quantile rule, minimum replay trace (20 evaluation records / 60 s, 5 calibration records) → 56 replayed
devices. Every run used the in-process form of the cloud service (`cloud.transport=local`), which gives decisions
identical to the deployed Cloud Run service (verified on 90 paired runs of protocol v3). The tables and figures of
the revised manuscript are generated from these files by `scripts/make_figures.py` into `easa_sim/figures/v4/`.
The run scripts are `run_v4/window_{A,B,C,T,R,O,V}.ps1`; the logs `log_*.txt` are their console output.

| File | Experiment (paper section) | Rows |
|---|---|---|
| `v4_main.csv` | the seven configurations of Table 5 × seeds 0–29 (§5.1–5.8) | 210 |
| `v4_ablation.csv` | EASA_net_binary (graded vs. binary, §5.3), EASA_reset and EASA_exit_net (release rules, §5.9) × seeds 0–29 | 90 |
| `v4_outage.csv` | EASA_full with cloud calls skipped for t ∈ [1800, 2700) s × seeds 0–29 (§5.7) | 30 |
| `v4_lowbattery.csv` | low-battery scenario e_d ~ U(0.10, 0.35): EASA_full, EASA_no_energy, B3_net_only × seeds 0–29 (§5.8) | 90 |
| `v4_reset.csv` | EASA_reset rows used for Supplementary Table S11 | 30 |
| `v4_sensitivity.csv` | one-at-a-time sweep (w_net, β, h, k, target FPR), EASA_full and B3_net_only × 10 seeds per point (§5.13, Supplementary S3) | 340 |
| `v4_partition_disjoint.csv`, `v4_partition_disjoint_minusC.csv`, `v4_partition_disjoint_device.csv` | training partitions `disjoint` / `disjoint_device` (§5.5, Table 10) | 90 / 30 / 90 |
| `v4_label_ms3_cap8.csv`, `v4_label_ms5_cap6.csv`, `v4_label_ms5_cap12.csv`, `v4_label_ms10_cap8.csv` | B3, EASA−PH, EASA × seeds 0–29 under alternative labelling rules (§5.10, Supplementary Table S24); the attacker sets are `iotdiad_attackers_ms*.json` | 90 each |
| `v4_load_x2.csv`, `v4_load_x3.csv`, `v4_hetero.csv` | device_multiplier 2 / 3 and the heterogeneous fleet, B3 and EASA × seeds 0–9 (§5.11, Supplementary Table S21) | 20 each |
| `v4_keep65_rest.csv` | 65-device reference (attacker hosts kept, quantile rule) for the response letter | 120 |
| `v4_toniot_truth.csv`, `v4_toniot_rule.csv` | TON_IoT replication under the dataset's labels and under the dominant-source rule, B3, EASA−PH, EASA × seeds 0–29 (§5.10, Table 15; availability = ts + duration, no duration cap) | 90 each |
| `v4_toniot_tr.csv` | TON_IoT, B3 and EASA × seeds 0–9 with all traces saved (input of the TON_IoT audits) | 20 |
| `toniot_label_check.json` | dominant-source rule vs. TON_IoT labels per attack type (Supplementary Table S9) | — |
| `toniot_devices.csv`, `toniot_device_scores_{b3,easa}.csv`, `toniot_audit*.csv`, `log_audit_protocol_toniot.txt` | TON_IoT device list, per-device network scores, recovery audit and protocol audit (Supplementary S7) | — |
| `v4_audit_all_seeds.csv`, `v4_audit_all_seeds_agg.csv` | recovery audit over all 30 seeds of `v4_main` (§5.9, Table 13) | — |
| `v4_lockin.csv`, `v4_lockin_agg.csv`, `v4_lockin_per_seed.csv` | lock-in attribution EASA vs. EASA−PH over all seeds (§5.9) | — |
| `v4_device_scores.csv`, `v4_device_scores_ph.csv` | per-device mean benign network score over seeds, EASA and EASA−PH (§5.9, §5.10) | — |
| `label_sensitivity_working_v4.csv` | label-rule grid applied to the v4 working pool (Supplementary Table S7) | 405 |
| `log_R.txt` | console output of `window_R.ps1` (hygiene manifest, B3_local, device holdout) | — |
| `log_audit_protocol_v4.txt` | output of `audit_protocol.py` on the v4 pool (Supplementary Table S8) | — |
| `v4_b3local.csv`, `v4_partition_disjoint_b3local.csv` | B3_local (network-only trust, locally trained MLP, no cloud) × seeds 0–29 under the shared and the disjoint partition: the model-sharing contrast B3-local → B3 (§5.2, §5.5) | 30 / 30 |
| `v4_holdout.csv`, `v4_holdout_split.csv` | federation-wide device holdout (`topology.global_holdout_devices_fraction=0.3333`, 18 devices excluded from every gateway's training), B3_local, B3, EASA−PH, EASA × seeds 0–29; `_split` = per-run metrics on held-out vs. seen devices from the traces (`audit_holdout_devices.py`) (§5.5, Table 10) | 120 / 240 |
| `hygiene_manifest.csv` | the seven attacker-host addresses removed from the benign chain, with rows per split (`audit_hygiene.py`; §4.2, §5.10, Supplementary Table S22) | 7 |
| `toniot_label_matrix.json` | host-level and row-level comparison of the dominant-source rule with the hosts TON_IoT documents as attackers (`toniot_label_matrix.py`; §5.10, Supplementary S7) | — |
| `v4c_main.csv`, `v4c_partition_disjoint.csv`, `v4c_contrasts.csv` | protocol v4c (identity-corrected attacker sets, `config/v4c.yaml`): B3_local, B3, EASA−PH, EASA, EASA binary × seeds 0–29 under shared training; B3_local, B3 under the disjoint partition; the four core contrasts (`core_contrasts.py`; §5.10, Table 14) | 150 / 60 / — |
| `devices_v4c.csv`, `hygiene_manifest_v4c.csv` | the 58 replayed devices and the six removed addresses under v4c | 58 / 6 |
| `iotdiad_packet_identity.json` | identity of the in-subnet source addresses in the first 100 MB of the IoT-DIAD *packet-based* release files (benign ×4, first file of each attack type concerned): (src_ip, released src_mac/device name, vendor prefix) counts; resolves the seven designated benign-chain addresses (`scripts/packet_identity_check.py`; §4.2, §5.10, Table 15, Supplementary Tables S17–S18; `designation_check` classifies every designated address of the retained types) | — |
| `devices_v4.csv` | the 56 replayed devices with trace lengths (`list_devices.py`; `run_v4/window_O.ps1`) | 56 |
| `env.txt` | Python and package versions, OS and GPU of the machine (§4.7) | — |
| `traces/v4_main/`, `traces/v4_ablation/`, `traces/v4_holdout/`, `traces/v4_toniot_tr/` | per-epoch, per-device logs of every seed (input of the audits and Figure 7); large, kept out of git except seed 0 | — |

Column notes as in `../README.md`; new columns: `n_devices`, `n_devices_excluded_short_trace`, `training_partition`,
`device_multiplier`, `global_holdout_devices_fraction`, `global_holdout_device_ids`, `n_clean_releases`, `wall_ms_per_epoch` (wall-clock decision cost per epoch for all devices
of all gateways), `protocol_hash` (hash of the protocol-relevant configuration keys).
