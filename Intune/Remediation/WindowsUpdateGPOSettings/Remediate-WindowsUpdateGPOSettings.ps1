#   Second script of two for GPO Endpoint Analytics Remediation
#   When a customer moves from GPOs to MDM profiles, or have
#   migrated from AD to AAD, residual GPO policies may stay

#   Remediate-WindowsUpdateGPOSettings.ps1
#   Function: Delete the WindowsUpdate reg key

#   Author: Tim Knapp

#   Change History
#   1.0 (2026-MAR-24):
#       - First release

[string]$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
[string]$regKeyName = ""

try {

    if(Test-Path -Path $regPath)
    {
        Write-Host "Reg key found, attempting to remove key: $regPath"
        Remove-Item -Path $regPath -Recurse -Force
        Exit 0
    }
    else {
        Write-Host "Reg key not found, no action needed"
        Exit 1
    }
}
catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 1
}
