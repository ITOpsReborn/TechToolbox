#   First script of two for GPO Endpoint Analytics Remediation
#   When a customer moves from GPOs to MDM profiles, or have
#   migrated from AD to AAD, residual GPO policies may stay

#   Detect-AUGPOPolicy.ps1
#   Function: Review a machines GPO policy folders for automatic
#               update policies. If policy folders are found
#               the script will return an error.  This will cause
#               endpoint analytics to run the remediation script

#   Author: Tim Knapp

#   Change History
#   1.0 (2022-MAR-04):
#       - First release

[string]$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
[string]$regKeyName = "NoAutoUpdate"

try {
    
    $test = Get-ItemProperty -Path $regPath -Name $regKeyName

    if($test)
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
    Write-Host "No_Match"
    exit 0
}


