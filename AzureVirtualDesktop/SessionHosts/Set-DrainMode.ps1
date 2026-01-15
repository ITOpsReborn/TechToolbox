<#
.SYNOPSIS
    Sets drain mode on Azure Virtual Desktop session hosts.

.DESCRIPTION
    This script enables or disables drain mode on session hosts, which prevents
    new user sessions while allowing existing sessions to continue. Useful for
    maintenance or decommissioning.

.PARAMETER HostPoolName
    The name of the host pool.

.PARAMETER ResourceGroupName
    The resource group name containing the host pool.

.PARAMETER SessionHostNames
    Array of session host names to set drain mode on.

.PARAMETER EnableDrainMode
    Switch to enable drain mode. If not specified, drain mode is disabled.

.PARAMETER AllSessionHosts
    Switch to apply to all session hosts in the host pool.

.EXAMPLE
    .\Set-DrainMode.ps1 -HostPoolName "HP-Production" -ResourceGroupName "RG-AVD" -SessionHostNames @("sh-001", "sh-002") -EnableDrainMode

.EXAMPLE
    .\Set-DrainMode.ps1 -HostPoolName "HP-Production" -ResourceGroupName "RG-AVD" -AllSessionHosts -EnableDrainMode

.NOTES
    Requires Az.DesktopVirtualization module and appropriate Azure RBAC permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$HostPoolName,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false)]
    [string[]]$SessionHostNames,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableDrainMode,
    
    [Parameter(Mandatory = $false)]
    [switch]$AllSessionHosts
)

try {
    Write-Host "Connecting to Azure..." -ForegroundColor Cyan
    
    $context = Get-AzContext
    if (-not $context) {
        Connect-AzAccount
    }

    if (-not $SessionHostNames -and -not $AllSessionHosts) {
        Write-Error "Please specify either SessionHostNames or use AllSessionHosts switch"
        exit 1
    }

    $targetHosts = @()

    if ($AllSessionHosts) {
        Write-Host "Retrieving all session hosts from host pool: $HostPoolName..." -ForegroundColor Cyan
        $allHosts = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName
        $targetHosts = $allHosts | ForEach-Object { $_.Name.Split('/')[1] }
    }
    else {
        $targetHosts = $SessionHostNames
    }

    Write-Host "Target session hosts: $($targetHosts.Count)" -ForegroundColor Cyan

    $successCount = 0
    $failCount = 0

    foreach ($hostName in $targetHosts) {
        try {
            $fullName = "$HostPoolName/$hostName"
            
            if ($EnableDrainMode) {
                Write-Host "  Enabling drain mode on: $hostName..." -ForegroundColor Yellow
                Update-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -Name $hostName -AllowNewSession:$false | Out-Null
                Write-Host "    ✓ Drain mode enabled" -ForegroundColor Green
            }
            else {
                Write-Host "  Disabling drain mode on: $hostName..." -ForegroundColor Cyan
                Update-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -Name $hostName -AllowNewSession:$true | Out-Null
                Write-Host "    ✓ Drain mode disabled" -ForegroundColor Green
            }
            
            $successCount++
        }
        catch {
            Write-Host "    ✗ Failed: $($_.Exception.Message)" -ForegroundColor Red
            $failCount++
        }
    }

    Write-Host "`nSummary:" -ForegroundColor Cyan
    Write-Host "  Total Processed: $($targetHosts.Count)" -ForegroundColor White
    Write-Host "  Successful: $successCount" -ForegroundColor Green
    Write-Host "  Failed: $failCount" -ForegroundColor Red
    
    if ($EnableDrainMode) {
        Write-Host "`nNote: Session hosts in drain mode will not accept new connections." -ForegroundColor Yellow
        Write-Host "Existing user sessions will remain active until users log off." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
