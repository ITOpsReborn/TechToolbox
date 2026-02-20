
<# 
.SYNOPSIS
  Removes ONLY legacy GPO-tattooed WHfB keys. 
  Explicitly preserves Intune CSP paths under:
    HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<TenantId>\Device\Policies

.AUTHOR: Tim Knapp

.RETURNS
  Exit 0 = Remediated/Compliant
  Exit 2 = Error
#>

try {
    $ErrorActionPreference = 'Stop'

    $logDir = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $log = Join-Path $logDir ("Remediate_PassportForWork_{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

    function Write-Log([string]$m) {
        $m | Tee-Object -FilePath $log -Append
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

    Write-Log ("Cleanup complete. RemovedGpoTattoo={0}" -f $removed)
    exit 0
}
catch {
    $_ | Out-String | Write-Log
    Write-Error $_.Exception.Message
    exit 2
}
