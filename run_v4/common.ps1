$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path results\v4 | Out-Null
function Run($label, $cmd) {
    $log = "results\v4\log_$($script:WIN).txt"
    "--- [$label] $(Get-Date)  $cmd" | Tee-Object -FilePath $log -Append
    Invoke-Expression $cmd 2>&1 | Tee-Object -FilePath $log -Append | Select-Object -Last 2
}
$C = "--config config\v4.yaml --set cloud.transport=local"
