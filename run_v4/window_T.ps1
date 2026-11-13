# Window T -- reduced replication on TON_IoT with ground-truth labels (editor point 1, R4). ~2.5 h
# Revision round 1 (internal review of the revised draft) rerun: availability = ts + duration with NO 120 s cap (data.toniot_duration_cap_s: null), plus the
# non-circular label check, the all-seed traces of B3/EASA and the audits.
# Requires data\TON_IoT\Network_dataset_{1,8,11,12,17,18,20,22,23}.csv (paths in config\v4_toniot.yaml).
$script:WIN = "T"; . .\run_v4\common.ps1
$T = "--config config\v4_toniot.yaml --set cloud.transport=local"
Run "T1 device list (TON_IoT pool)"                 "python scripts\list_devices.py --config config\v4_toniot.yaml --out results\v4\toniot_devices.csv"
Run "T2 protocol audit (TON_IoT pool)"              "python scripts\audit_protocol.py --config config\v4_toniot.yaml > results\v4\log_audit_protocol_toniot.txt"
Run "T3 label check: rule vs dataset labels, hosts" "python scripts\toniot_label_matrix.py --config config\v4_toniot.yaml --out results\v4\toniot_label_matrix.json"
Run "T4 grid under TRUE labels"                     "python scripts\run_experiments.py $T --set data.toniot_label_mode=truth --configs B3_net_only EASA_net_score EASA_full --out results\v4\v4_toniot_truth.csv --fresh"
Run "T5 grid under the dominant-source RULE labels" "python scripts\run_experiments.py $T --set data.toniot_label_mode=dominant_src --configs B3_net_only EASA_net_score EASA_full --out results\v4\v4_toniot_rule.csv --fresh"
Run "T6 traces for the audits (truth labels, 10 seeds)" "python scripts\run_experiments.py $T --set data.toniot_label_mode=truth --configs B3_net_only EASA_full --save-all-traces --seeds 10 --out results\v4\v4_toniot_tr.csv --fresh"
Run "T7 device scores (B3)"                         "python scripts\audit_device_scores.py results\traces\v4_toniot_tr --config B3_net_only --out results\v4\toniot_device_scores_b3.csv"
Run "T8 device scores (EASA)"                       "python scripts\audit_device_scores.py results\traces\v4_toniot_tr --config EASA_full --out results\v4\toniot_device_scores_easa.csv"
Run "T9 recovery audit"                             "python scripts\audit_recovery.py results\traces\v4_toniot_tr --out results\v4\toniot_audit.csv"
Copy-Item results\toniot_label_check.json results\v4\toniot_label_check.json -Force
"=== window T done $(Get-Date) ===" | Tee-Object -FilePath results\v4\log_T.txt -Append
