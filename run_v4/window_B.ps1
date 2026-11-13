# Window B -- sensitivity sweep + label-rule robustness (protocol v4). ~6 h
$script:WIN = "B"; . .\run_v4\common.ps1
Run "B1 sensitivity sweep (17 points x 2 configs x 10 seeds)" "python scripts\sweep.py --config config\v4.yaml --out results\v4\v4_sensitivity.csv --fresh"
Run "B2 label ms3/cap8"  "python scripts\run_experiments.py $C --set data.iotdiad_min_share=0.03 --configs B3_net_only EASA_net_score EASA_full --out results\v4\v4_label_ms3_cap8.csv"
Run "B3 label ms5/cap6"  "python scripts\run_experiments.py $C --set data.iotdiad_max_attackers=6 --configs B3_net_only EASA_net_score EASA_full --out results\v4\v4_label_ms5_cap6.csv"
Run "B4 label ms5/cap12" "python scripts\run_experiments.py $C --set data.iotdiad_max_attackers=12 --configs B3_net_only EASA_net_score EASA_full --out results\v4\v4_label_ms5_cap12.csv"
Run "B5 label ms10/cap8" "python scripts\run_experiments.py $C --set data.iotdiad_min_share=0.10 --configs B3_net_only EASA_net_score EASA_full --out results\v4\v4_label_ms10_cap8.csv 2>&1 | Out-File -Append results\v4\log_B5_ms10.txt"
"=== window B done $(Get-Date) ===" | Tee-Object -FilePath results\v4\log_B.txt -Append
