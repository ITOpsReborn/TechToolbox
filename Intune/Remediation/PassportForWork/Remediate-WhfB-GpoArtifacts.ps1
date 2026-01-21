
<# 
.SYNOPSIS
  Removes ONLY legacy GPO-tattooed WHfB keys. 
  Explicitly preserves Intune CSP paths under:
    HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<TenantId>\Device\Policies

.RETURNS
  Exit 0 = Remediated/Compliant
  Exit 2 = Error
#>

[CmdletBinding()]

[string]$TenantId = ""

try {
    $ErrorActionPreference = 'Stop'

    $logDir = 'C:\ProgramData\Intune-PR\WHfB-CKCT'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $log = Join-Path $logDir ("Remediate_{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

    function Write-Log([string]$m) {
        $m | Tee-Object -FilePath $log -Append | Out-Null
    }

    Write-Log "Starting CKCT-safe WHfB GPO cleanup. TenantId=$TenantId"

    # --- ABSOLUTE GUARDRAIL: DO NOT TOUCH CSP/MDM PATHS ---
    $CspPreserveRoots = @(
        "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\$TenantId",
        "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\$TenantId\Device",
        "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\$TenantId\Device\Policies"
    )
    foreach ($p in $CspPreserveRoots) {
        if (Test-Path $p) { Write-Log "PRESERVE (CSP): $p" }
    }

    # --- REMOVE ONLY GPO TATTOOS ---
    $GpoTattooRoots = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
    )
    
    $LegacyCustomTattooRoots = @(
        "HKLM:\SOFTWARE\WHfBPolicy"   # example; include any org-specific legacy paths
    )

    $removed = $false
    foreach ($root in ($GpoTattooRoots + $LegacyCustomTattooRoots)) {
        if (Test-Path $root) {
            Write-Log "Removing legacy GPO tattoo root: $root"
            Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
            $removed = $true
        }
    }

    # Nudge an MDM sync so CSP re-applies (graceful if task not found)
    try {
        Write-Log "Triggering MDM sync task..."
        schtasks /Run /TN "\Microsoft\Windows\EnterpriseMgmt\Schedule #3 created by enrollment client" | Out-Null
    } catch {
        Write-Log "MDM sync task trigger not found (non-fatal)."
    }

    Write-Log ("Cleanup complete. RemovedGpoTattoo={0}" -f $removed)
    exit 0
}
catch {
    $_ | Out-String | Write-Log
    Write-Error $_.Exception.Message
    exit 2
}
