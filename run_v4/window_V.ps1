# Window V -- revision round 1, internal draft review 2: identity-corrected labels (protocol v4c). ~1.7 h
#   V1 device list and hygiene manifest under v4c                                            ~6 min
#   V2 the four core contrasts under v4c: B3_local, B3, EASA-PH, EASA, EASA-PH binary; 30 seeds   ~1.2 h
#   V3 model-sharing contrast under the disjoint partition (B3_local, B3); 30 seeds            ~25 min
$script:WIN = "V"; . .\run_v4\common.ps1
$V = "--config config\v4c.yaml --set cloud.transport=local"
Run "V1a device list (v4c)"            "python scripts\list_devices.py --config config\v4c.yaml --out results\v4\devices_v4c.csv"
Run "V1b hygiene manifest (v4c)"       "python scripts\audit_hygiene.py --config config\v4c.yaml --out results\v4\hygiene_manifest_v4c.csv"
Run "V2 core contrasts (v4c)"          "python scripts\run_experiments.py $V --configs B3_local B3_net_only EASA_net_score EASA_full EASA_net_binary --out results\v4\v4c_main.csv --fresh"
Run "V3 disjoint partition (v4c)"      "python scripts\run_experiments.py $V --set topology.training_partition=disjoint --configs B3_local B3_net_only --out results\v4\v4c_partition_disjoint.csv --fresh"
"=== window V done $(Get-Date) ===" | Tee-Object -FilePath results\v4\log_V.txt -Append
