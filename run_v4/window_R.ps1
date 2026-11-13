# Window R -- revision round 1, additions after the internal review of the revised draft. ~3 h
#   R1 hygiene manifest (the 7 attacker-host addresses, rows per split)          ~3 min
#   R2 model-sharing contrast: B3_local (network-only score, local training, no registry), shared and disjoint   ~40 min
#   R3 federation-wide device holdout (every 3rd replayed device excluded from ALL training), 4 configs, traces  ~1.5 h
$script:WIN = "R"; . .\run_v4\common.ps1
Run "R1 hygiene manifest"                           "python scripts\audit_hygiene.py --config config\v4.yaml --out results\v4\hygiene_manifest.csv"
Run "R2a B3_local, shared training"                 "python scripts\run_experiments.py $C --configs B3_local --out results\v4\v4_b3local.csv --fresh"
Run "R2b B3_local, disjoint partition"              "python scripts\run_experiments.py $C --set topology.training_partition=disjoint --configs B3_local --out results\v4\v4_partition_disjoint_b3local.csv --fresh"
Run "R3a global device holdout (1/3 of devices)"    "python scripts\run_experiments.py $C --set topology.global_holdout_devices_fraction=0.3333 --save-all-traces --configs B3_local B3_net_only EASA_net_score EASA_full --out results\v4\v4_holdout.csv --fresh"
Run "R3b held-out vs seen device metrics"           "python scripts\audit_holdout_devices.py results\traces\v4_holdout --results results\v4\v4_holdout.csv --out results\v4\v4_holdout_split.csv"
"=== window R done $(Get-Date) ===" | Tee-Object -FilePath results\v4\log_R.txt -Append
