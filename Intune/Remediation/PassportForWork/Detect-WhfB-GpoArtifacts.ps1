
<#
.SYNOPSIS
  Detects legacy WHfB GPO tattoos that can conflict with CKCT while preserving Intune CSP.

.AUTHOR: Tim Knapp

.RETURNS
  Exit 0 = Compliant (no GPO tattoos)
  Exit 1 = Needs remediation (GPO tattoos found)
  Exit 2 = Error
#>

try {
    $ErrorActionPreference = 'Stop'

    # --- TARGET (GPO tattoos ONLY) ---
    # Legacy GPO tattoo location:
    # HKLM\SOFTWARE\Policies\Microsoft\PassportForWork
    $GpoTattooRoots = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
    )

    # Optional: org‑specific legacy custom locations
    $LegacyCustomTattooRoots = @(
        "HKLM:\SOFTWARE\WHfBPolicy"  # example legacy vendor key; safe to remove if present
    )

    function Test-Key([string]$Path) {
        try { return Test-Path -Path $Path -ErrorAction Stop } catch { return $false }
    }

    $needsRemediation = $false
    $report = New-Object System.Collections.Generic.List[string]

    # Look for GPO tattoos
    $interestingNames = @(
        'Enabled','UseCertificateForOnPremAuth','UseCloudTrustForOnPremAuth',
        'PINComplexity','UseEnhancedAntiSpoofing','AllowBioMetrics', 'DisablePostLogonProvisioning',
        'RequireSecurityDevice','MinPINLength','MaxPINLength','LockoutThreshold'
    )

    foreach ($root in ($GpoTattooRoots + $LegacyCustomTattooRoots)) {
        if (Test-Key $root) {
            $needsRemediation = $true
            $report.Add("FOUND GPO tattoo root: $root")
            foreach ($name in $interestingNames) {
                try {
                    $val = Get-ItemProperty -Path $root -Name $name -ErrorAction SilentlyContinue
                    if ($null -ne $val) { $report.Add("  $name = $($val.$name)") }
                } catch {}
            }
        }
    }

    $report | ForEach-Object { Write-Output $_ }

    if ($needsRemediation) {
        exit 1
    } else {
        exit 0
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 2
}
