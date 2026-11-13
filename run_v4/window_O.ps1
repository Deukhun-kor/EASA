# Window O -- optional items after the internal review of the revised draft (revision round 1). ~10 min
#   O1 device list of protocol v4 (results\v4\devices_v4.csv)
#   O2 listing of the IoT-DIAD portal (all folders, no download) -> results\v4\portal_listing.txt, for the packet-CSV identity check
#      (the portal answers 403 until its download form has been submitted in a browser; see RUN_R1.md)
$script:WIN = "O"; . "$PSScriptRoot\common.ps1"
Run "O1 device list (v4)"      "python scripts\list_devices.py --config config\v4.yaml --out results\v4\devices_v4.csv"
Run "O2 portal listing"        "python scripts\download_iotdiad.py --dry-run --root . 2>&1 | Out-File -Encoding utf8 results\v4\portal_listing.txt"
"--- window O done $(Get-Date)" | Tee-Object -FilePath results\v4\log_O.txt -Append
