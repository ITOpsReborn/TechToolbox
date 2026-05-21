#   First script of two for GPO Endpoint Analytics Remediation
#   When a customer moves from GPOs to MDM profiles, or have
#   migrated from AD to AAD, residual GPO policies may stay

#   Detect-WindowsUpdateGPOSettings.ps1
#   Function: Review a machines GPO policy folders for Windows
#               update policies. If policy folders are found
#               the script will return an error.  This will cause
#               endpoint analytics to run the remediation script

#   Author: Tim Knapp (Microsoft)

#   Change History
#   1.0 (2026-MAR-24:
#       - First release

[string]$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
[string]$regKeyName = ""

try {

    if(Test-Path -Path $regPath)
    {
        Write-Host "Match"
        Exit 1
    }
    else {
        Write-Host "No_Match"
        Exit 0
    }
}
catch {
    Write-Host "Exception Found: $($_.Exception.Message)"
    exit 0
}


