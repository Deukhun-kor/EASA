# Run ONCE before the final v4 grid: archives yesterday's v4 results (protocol without the minimum-trace rule)
# so that every grid starts fresh. Keeps them under results\v4_prelim\ for the record.
Move-Item -Force results\v4 results\v4_prelim -ErrorAction SilentlyContinue
Move-Item -Force results\traces\v4_main results\traces\v4_prelim_main -ErrorAction SilentlyContinue
Move-Item -Force results\traces\v4_ablation results\traces\v4_prelim_ablation -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path results\v4 | Out-Null
"reset done -> previous results in results\v4_prelim"
