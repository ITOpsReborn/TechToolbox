#   First script of two to detect the startup type for
#   Connected User Experiences and Telemetry (DiagTrack)

#   Detect-DiagTrack-Startup.ps1
#   Function: Review a machine's Connected User Experiences and Telemetry (DiagTrack).
#               If the service startup type is not set Automatic, script will exit 1
#               forcing remediation to run. 

#   Author: Tim Knapp

#   Change History
#   1.0 (2024-JUL-23):
#       - First release

[string]$startType = Get-Service DiagTrack | Select-Object -ExpandProperty StartType

try {

    if($startType -ne "Automatic")
    {
        Write-Host "Match"
        Exit 1
    }
    else {
        Write-Output "No_Match"
        Exit 0
    }
}
catch {
    Write-Host "No_Match"
    exit 0
}


