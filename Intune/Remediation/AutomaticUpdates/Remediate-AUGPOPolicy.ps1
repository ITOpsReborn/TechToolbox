#   Second script of two for GPO Endpoint Analytics Remediation
#   When a customer moves from GPOs to MDM profiles, or have
#   migrated from AD to AAD, residual GPO policies may stay

#   Remidate-AUGPOPolicy.ps1
#   Function: Delete the NoAutoUpdate reg key

#   Author: Tim Knapp

#   Change History
#   1.0 (2022-MAR-04):
#       - First release

[string]$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
[string]$regKeyName = "NoAutoUpdate"

try {
    
    Remove-ItemProperty -Path $regPath -Name $regKeyName -Force
    exit 0

}
catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 1
}
