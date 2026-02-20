#   Second script to configure Connected User Experiences and Telemetry
#   to start automatically

#   Remediate-DiagTrack-Startup.ps1
#   Function: Sets DiagTrack service to automatic

#   Author: Tim Knapp

#   Change History
#   1.0 (2024-JUL-23):
#       - First release

[string]$serviceName = "DiagTrack"

try {
    
    Set-Service -Name $serviceName -StartupType Automatic
    exit 0

}
catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 1
}
