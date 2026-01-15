<#
.SYNOPSIS
    Exports all Conditional Access policies from Entra ID.

.DESCRIPTION
    This script exports all Conditional Access policies to JSON format for backup,
    documentation, or migration purposes.

.PARAMETER OutputPath
    The directory path where JSON files will be saved.

.PARAMETER IncludeDisabled
    If specified, includes disabled policies in the export.

.EXAMPLE
    .\Export-ConditionalAccessPolicies.ps1 -OutputPath "C:\Backup\CA"

.EXAMPLE
    .\Export-ConditionalAccessPolicies.ps1 -OutputPath "C:\Backup\CA" -IncludeDisabled

.NOTES
    Requires Microsoft.Graph.Identity.SignIns module and Policy.Read.All permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\ConditionalAccessBackup",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled
)

try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome
    }

    # Create output directory if it doesn't exist
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    Write-Host "Retrieving Conditional Access policies..." -ForegroundColor Cyan
    $policies = Get-MgIdentityConditionalAccessPolicy -All

    if (-not $IncludeDisabled) {
        $policies = $policies | Where-Object { $_.State -eq "enabled" }
    }

    Write-Host "Found $($policies.Count) policies" -ForegroundColor Green

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $summaryReport = @()

    foreach ($policy in $policies) {
        # Sanitize filename
        $fileName = $policy.DisplayName -replace '[\\/:*?"<>|]', '_'
        $filePath = Join-Path $OutputPath "$fileName.json"
        
        # Export policy to JSON
        $policy | ConvertTo-Json -Depth 10 | Set-Content -Path $filePath -Encoding UTF8
        
        Write-Host "  ✓ Exported: $($policy.DisplayName)" -ForegroundColor Green

        # Add to summary
        $summaryReport += [PSCustomObject]@{
            DisplayName           = $policy.DisplayName
            State                 = $policy.State
            CreatedDateTime       = $policy.CreatedDateTime
            ModifiedDateTime      = $policy.ModifiedDateTime
            IncludeUsers          = ($policy.Conditions.Users.IncludeUsers -join "; ")
            IncludeApplications   = ($policy.Conditions.Applications.IncludeApplications -join "; ")
            GrantControls         = ($policy.GrantControls.BuiltInControls -join "; ")
            FileName              = "$fileName.json"
        }
    }

    # Export summary report
    $summaryPath = Join-Path $OutputPath "PolicySummary_$timestamp.csv"
    $summaryReport | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n✓ Export completed successfully!" -ForegroundColor Green
    Write-Host "  Location: $OutputPath" -ForegroundColor White
    Write-Host "  Policies Exported: $($policies.Count)" -ForegroundColor White
    Write-Host "  Summary Report: $summaryPath" -ForegroundColor White
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
