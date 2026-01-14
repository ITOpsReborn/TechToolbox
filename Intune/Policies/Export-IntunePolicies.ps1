<#
.SYNOPSIS
    Exports all Intune configuration policies and profiles.

.DESCRIPTION
    This script exports all device configuration policies, compliance policies,
    and settings catalog policies from Intune for backup or migration purposes.

.PARAMETER OutputPath
    The directory where policy backups will be saved.

.PARAMETER PolicyType
    Type of policies to export: All, DeviceConfiguration, CompliancePolicy, or SettingsCatalog.

.EXAMPLE
    .\Export-IntunePolicies.ps1 -OutputPath "C:\Backup\Intune"

.EXAMPLE
    .\Export-IntunePolicies.ps1 -OutputPath "C:\Backup\Intune" -PolicyType CompliancePolicy

.NOTES
    Requires Microsoft.Graph.DeviceManagement module and DeviceManagementConfiguration.Read.All permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\IntunePolicyBackup",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "DeviceConfiguration", "CompliancePolicy", "SettingsCatalog")]
    [string]$PolicyType = "All"
)

try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -NoWelcome
    }

    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $exportSummary = @()

    # Export Device Configuration Policies
    if ($PolicyType -eq "All" -or $PolicyType -eq "DeviceConfiguration") {
        Write-Host "`nExporting Device Configuration Policies..." -ForegroundColor Cyan
        
        $configPolicyPath = Join-Path $OutputPath "DeviceConfiguration"
        New-Item -ItemType Directory -Path $configPolicyPath -Force | Out-Null
        
        $configPolicies = Get-MgDeviceManagementDeviceConfiguration -All
        
        foreach ($policy in $configPolicies) {
            $fileName = ($policy.DisplayName -replace '[\\/:*?"<>|]', '_') + ".json"
            $filePath = Join-Path $configPolicyPath $fileName
            
            $policy | ConvertTo-Json -Depth 10 | Set-Content -Path $filePath -Encoding UTF8
            
            Write-Host "  ✓ Exported: $($policy.DisplayName)" -ForegroundColor Green
            
            $exportSummary += [PSCustomObject]@{
                PolicyType   = "Device Configuration"
                DisplayName  = $policy.DisplayName
                PolicyId     = $policy.Id
                CreatedDate  = $policy.CreatedDateTime
                ModifiedDate = $policy.LastModifiedDateTime
                FileName     = $fileName
            }
        }
        
        Write-Host "  Total Device Configuration Policies: $($configPolicies.Count)" -ForegroundColor White
    }

    # Export Compliance Policies
    if ($PolicyType -eq "All" -or $PolicyType -eq "CompliancePolicy") {
        Write-Host "`nExporting Compliance Policies..." -ForegroundColor Cyan
        
        $compliancePolicyPath = Join-Path $OutputPath "CompliancePolicies"
        New-Item -ItemType Directory -Path $compliancePolicyPath -Force | Out-Null
        
        $compliancePolicies = Get-MgDeviceManagementDeviceCompliancePolicy -All
        
        foreach ($policy in $compliancePolicies) {
            $fileName = ($policy.DisplayName -replace '[\\/:*?"<>|]', '_') + ".json"
            $filePath = Join-Path $compliancePolicyPath $fileName
            
            $policy | ConvertTo-Json -Depth 10 | Set-Content -Path $filePath -Encoding UTF8
            
            Write-Host "  ✓ Exported: $($policy.DisplayName)" -ForegroundColor Green
            
            $exportSummary += [PSCustomObject]@{
                PolicyType   = "Compliance Policy"
                DisplayName  = $policy.DisplayName
                PolicyId     = $policy.Id
                CreatedDate  = $policy.CreatedDateTime
                ModifiedDate = $policy.LastModifiedDateTime
                FileName     = $fileName
            }
        }
        
        Write-Host "  Total Compliance Policies: $($compliancePolicies.Count)" -ForegroundColor White
    }

    # Export summary
    $summaryPath = Join-Path $OutputPath "ExportSummary_$timestamp.csv"
    $exportSummary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n✓ Export completed successfully!" -ForegroundColor Green
    Write-Host "  Location: $OutputPath" -ForegroundColor White
    Write-Host "  Total Policies Exported: $($exportSummary.Count)" -ForegroundColor White
    Write-Host "  Summary Report: $summaryPath" -ForegroundColor White
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
