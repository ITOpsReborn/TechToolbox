<#
.SYNOPSIS
    Exports all Windows 365 provisioning policies.

.DESCRIPTION
    This script exports all Cloud PC provisioning policies including their configuration,
    assignments, and Azure network connection details.

.PARAMETER OutputPath
    The directory where policy exports will be saved.

.EXAMPLE
    .\Export-ProvisioningPolicies.ps1 -OutputPath "C:\Backup\Windows365"

.NOTES
    Requires Microsoft.Graph.DeviceManagement module and CloudPC.Read.All permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Windows365_Provisioning_Backup"
)

try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "CloudPC.Read.All" -NoWelcome
    }

    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    Write-Host "Retrieving provisioning policies..." -ForegroundColor Cyan
    $policies = Get-MgDeviceManagementVirtualEndpointProvisioningPolicy -All

    Write-Host "Found $($policies.Count) provisioning policies" -ForegroundColor Green

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $policySummary = @()

    foreach ($policy in $policies) {
        # Export policy details
        $fileName = ($policy.DisplayName -replace '[\\/:*?"<>|]', '_') + ".json"
        $filePath = Join-Path $OutputPath $fileName
        
        $policy | ConvertTo-Json -Depth 10 | Set-Content -Path $filePath -Encoding UTF8
        
        Write-Host "  ✓ Exported: $($policy.DisplayName)" -ForegroundColor Green

        # Get assignments for this policy
        $assignments = Get-MgDeviceManagementVirtualEndpointProvisioningPolicyAssignment -ProvisioningPolicyId $policy.Id -All
        
        $policySummary += [PSCustomObject]@{
            DisplayName               = $policy.DisplayName
            PolicyId                  = $policy.Id
            ImageType                 = $policy.ImageType
            ImageId                   = $policy.ImageId
            CloudPcGroupDisplayName   = $policy.CloudPcGroupDisplayName
            OnPremisesConnectionId    = $policy.OnPremisesConnectionId
            AssignmentCount           = $assignments.Count
            FileName                  = $fileName
        }

        # Export assignments
        if ($assignments.Count -gt 0) {
            $assignmentFile = ($policy.DisplayName -replace '[\\/:*?"<>|]', '_') + "_Assignments.json"
            $assignmentPath = Join-Path $OutputPath $assignmentFile
            $assignments | ConvertTo-Json -Depth 10 | Set-Content -Path $assignmentPath -Encoding UTF8
        }
    }

    # Export Azure Network Connections
    Write-Host "`nRetrieving Azure Network Connections..." -ForegroundColor Cyan
    $connections = Get-MgDeviceManagementVirtualEndpointOnPremisesConnection -All
    
    if ($connections.Count -gt 0) {
        $connectionsFile = Join-Path $OutputPath "AzureNetworkConnections_$timestamp.json"
        $connections | ConvertTo-Json -Depth 10 | Set-Content -Path $connectionsFile -Encoding UTF8
        Write-Host "  ✓ Exported $($connections.Count) Azure Network Connections" -ForegroundColor Green
    }

    # Export summary
    $summaryPath = Join-Path $OutputPath "ProvisioningPolicySummary_$timestamp.csv"
    $policySummary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n✓ Export completed successfully!" -ForegroundColor Green
    Write-Host "  Location: $OutputPath" -ForegroundColor White
    Write-Host "  Policies Exported: $($policies.Count)" -ForegroundColor White
    Write-Host "  Summary Report: $summaryPath" -ForegroundColor White
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
