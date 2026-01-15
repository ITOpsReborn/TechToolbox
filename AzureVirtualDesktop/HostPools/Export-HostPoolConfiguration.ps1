<#
.SYNOPSIS
    Exports Azure Virtual Desktop host pool configurations.

.DESCRIPTION
    This script exports all host pool configurations including their properties,
    application groups, and workspace assignments for backup or documentation.

.PARAMETER HostPoolName
    Optional filter for a specific host pool.

.PARAMETER ResourceGroupName
    Optional resource group name (required if HostPoolName is specified).

.PARAMETER OutputPath
    The directory where exports will be saved.

.EXAMPLE
    .\Export-HostPoolConfiguration.ps1 -OutputPath "C:\Backup\AVD"

.EXAMPLE
    .\Export-HostPoolConfiguration.ps1 -HostPoolName "HP-Production" -ResourceGroupName "RG-AVD" -OutputPath "C:\Backup\AVD"

.NOTES
    Requires Az.DesktopVirtualization module and appropriate Azure RBAC permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$HostPoolName,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\AVD_HostPool_Backup"
)

try {
    Write-Host "Connecting to Azure..." -ForegroundColor Cyan
    
    $context = Get-AzContext
    if (-not $context) {
        Connect-AzAccount
    }

    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $hostPoolSummary = @()

    if ($HostPoolName -and $ResourceGroupName) {
        $hostPools = @(Get-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName)
    }
    else {
        Write-Host "Retrieving all host pools..." -ForegroundColor Cyan
        $hostPools = Get-AzWvdHostPool
    }

    Write-Host "Found $($hostPools.Count) host pool(s)" -ForegroundColor Green

    foreach ($hp in $hostPools) {
        $hpName = $hp.Name
        $rgName = $hp.Id.Split('/')[4]
        
        Write-Host "`nProcessing host pool: $hpName..." -ForegroundColor Cyan
        
        # Create directory for this host pool
        $hpPath = Join-Path $OutputPath $hpName
        New-Item -ItemType Directory -Path $hpPath -Force | Out-Null
        
        # Export host pool configuration
        $hpConfigFile = Join-Path $hpPath "HostPool_Configuration.json"
        $hp | ConvertTo-Json -Depth 10 | Set-Content -Path $hpConfigFile -Encoding UTF8
        Write-Host "  ✓ Host pool configuration exported" -ForegroundColor Green
        
        # Get and export application groups
        $appGroups = Get-AzWvdApplicationGroup -ResourceGroupName $rgName | Where-Object { $_.HostPoolArmPath -eq $hp.Id }
        
        if ($appGroups) {
            $appGroupsFile = Join-Path $hpPath "ApplicationGroups.json"
            $appGroups | ConvertTo-Json -Depth 10 | Set-Content -Path $appGroupsFile -Encoding UTF8
            Write-Host "  ✓ Application groups exported ($($appGroups.Count) groups)" -ForegroundColor Green
            
            # Export applications for each RemoteApp application group
            foreach ($ag in $appGroups) {
                if ($ag.ApplicationGroupType -eq "RemoteApp") {
                    $agName = $ag.Name
                    $apps = Get-AzWvdApplication -ApplicationGroupName $agName -ResourceGroupName $rgName
                    
                    if ($apps) {
                        $appsFile = Join-Path $hpPath "Applications_$agName.json"
                        $apps | ConvertTo-Json -Depth 10 | Set-Content -Path $appsFile -Encoding UTF8
                        Write-Host "  ✓ Applications exported for $agName ($($apps.Count) apps)" -ForegroundColor Green
                    }
                }
            }
        }
        
        # Get session hosts
        $sessionHosts = Get-AzWvdSessionHost -HostPoolName $hpName -ResourceGroupName $rgName
        $sessionHostsFile = Join-Path $hpPath "SessionHosts.json"
        $sessionHosts | ConvertTo-Json -Depth 10 | Set-Content -Path $sessionHostsFile -Encoding UTF8
        Write-Host "  ✓ Session hosts exported ($($sessionHosts.Count) hosts)" -ForegroundColor Green
        
        # Add to summary
        $hostPoolSummary += [PSCustomObject]@{
            HostPoolName         = $hpName
            ResourceGroupName    = $rgName
            Location             = $hp.Location
            HostPoolType         = $hp.HostPoolType
            LoadBalancerType     = $hp.LoadBalancerType
            MaxSessionLimit      = $hp.MaxSessionLimit
            ValidationEnvironment = $hp.ValidationEnvironment
            SessionHostCount     = $sessionHosts.Count
            ApplicationGroupCount = $appGroups.Count
            ExportPath           = $hpPath
        }
    }

    # Export summary
    $summaryPath = Join-Path $OutputPath "HostPoolSummary_$timestamp.csv"
    $hostPoolSummary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n✓ Export completed successfully!" -ForegroundColor Green
    Write-Host "  Location: $OutputPath" -ForegroundColor White
    Write-Host "  Host Pools Exported: $($hostPools.Count)" -ForegroundColor White
    Write-Host "  Summary Report: $summaryPath" -ForegroundColor White
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
