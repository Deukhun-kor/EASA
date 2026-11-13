# Window A -- main grid of the revised manuscript (protocol v4). ~5 h
$script:WIN = "A"; . .\run_v4\common.ps1
Run "A1 main grid (7 configs, traces for all seeds)" "python scripts\run_experiments.py $C --save-all-traces --configs B0_static B1_vnsf B2_rules B3_net_only EASA_minus_C EASA_net_score EASA_full --out results\v4\v4_main.csv"
Run "A2 binary / reset / exit-net ablations"        "python scripts\run_experiments.py $C --save-all-traces --configs EASA_net_binary EASA_reset EASA_exit_net --out results\v4\v4_ablation.csv"
Run "A3 outage"                                     "python scripts\run_experiments.py $C --configs EASA_full --set cloud.outage.enabled=true --out results\v4\v4_outage.csv"
Run "A4 low battery"                                "python scripts\run_experiments.py $C --configs EASA_full EASA_no_energy B3_net_only --set `"posture.init_energy_range=[0.10, 0.35]`" --out results\v4\v4_lowbattery.csv"
Run "A5 recovery audit (all seeds)"                 "python scripts\audit_recovery.py results\traces\v4_main --out results\v4\v4_audit_all_seeds.csv"
Run "A6 lock-in attribution"                        "python scripts\audit_lockin.py results\traces\v4_main --results results\v4\v4_main.csv --out results\v4\v4_lockin.csv"
Run "A7 device scores (EASA)"                       "python scripts\audit_device_scores.py results\traces\v4_main --config EASA_full --out results\v4\v4_device_scores.csv"
Run "A8 device scores (EASA-PH)"                    "python scripts\audit_device_scores.py results\traces\v4_main --config EASA_net_score --out results\v4\v4_device_scores_ph.csv"
Run "A9 protocol audit (v4 pool)"                   "python scripts\audit_protocol.py --config config\v4.yaml > results\v4\log_audit_protocol_v4.txt"
Run "A10 label sensitivity on working data (v4)"    "python scripts\label_sensitivity_working.py --config config\v4.yaml --out results\v4\label_sensitivity_working_v4.csv"
"=== window A done $(Get-Date) ===" | Tee-Object -FilePath results\v4\log_A.txt -Append
