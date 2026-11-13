# After all three windows finished: one zip with everything to send.
Copy-Item results\traces\v4_main\EASA_full_seed0.parquet, results\traces\v4_main\EASA_net_score_seed0.parquet results\v4\ -ErrorAction SilentlyContinue
Compress-Archive -Force -Path results\v4\*.csv, results\v4\*.txt, results\v4\*.parquet, data\IoT-DIAD-2024\flow\iotdiad_attackers*.json -DestinationPath results\v4_results.zip
"-> results\v4_results.zip"
