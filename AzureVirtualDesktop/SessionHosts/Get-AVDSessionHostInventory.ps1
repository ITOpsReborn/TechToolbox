<#
.SYNOPSIS
    Generates a comprehensive inventory report of all Azure Virtual Desktop session hosts.

.DESCRIPTION
    This script retrieves detailed information about all AVD session hosts including
    their status, assigned users (for personal desktops), resource consumption, and health.

.PARAMETER HostPoolName
    Optional filter for a specific host pool.

.PARAMETER ResourceGroupName
    Optional resource group name (required if HostPoolName is specified).

.PARAMETER OutputPath
    The path where the CSV report will be saved.

.EXAMPLE
    .\Get-AVDSessionHostInventory.ps1 -OutputPath "C:\Reports\SessionHosts.csv"

.EXAMPLE
    .\Get-AVDSessionHostInventory.ps1 -HostPoolName "HP-Production" -ResourceGroupName "RG-AVD" -OutputPath "C:\Reports\SessionHosts.csv"

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
    [string]$OutputPath = ".\AVD_SessionHosts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

try {
    Write-Host "Connecting to Azure..." -ForegroundColor Cyan
    
    $context = Get-AzContext
    if (-not $context) {
        Connect-AzAccount
    }

    Write-Host "Current Subscription: $($context.Subscription.Name)" -ForegroundColor Cyan

    $inventory = @()

    if ($HostPoolName -and $ResourceGroupName) {
        # Get session hosts from specific host pool
        Write-Host "Retrieving session hosts from host pool: $HostPoolName..." -ForegroundColor Cyan
        $sessionHosts = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName
        
        foreach ($sh in $sessionHosts) {
            $inventory += [PSCustomObject]@{
                HostPoolName        = $HostPoolName
                ResourceGroupName   = $ResourceGroupName
                SessionHostName     = $sh.Name.Split('/')[1]
                Status              = $sh.Status
                AllowNewSession     = $sh.AllowNewSession
                AssignedUser        = $sh.AssignedUser
                Sessions            = $sh.Session
                LastHeartBeat       = $sh.LastHeartBeat
                AgentVersion        = $sh.AgentVersion
                VirtualMachineName  = $sh.ResourceId.Split('/')[-1]
                UpdateState         = $sh.UpdateState
                OSVersion           = $sh.OSVersion
            }
        }
    }
    else {
        # Get all host pools in subscription
        Write-Host "Retrieving all host pools in subscription..." -ForegroundColor Cyan
        $hostPools = Get-AzWvdHostPool
        
        Write-Host "Found $($hostPools.Count) host pools" -ForegroundColor Green

        foreach ($hp in $hostPools) {
            $hpName = $hp.Name
            $rgName = $hp.Id.Split('/')[4]
            
            Write-Host "  Processing host pool: $hpName..." -ForegroundColor Cyan
            
            $sessionHosts = Get-AzWvdSessionHost -HostPoolName $hpName -ResourceGroupName $rgName
            
            foreach ($sh in $sessionHosts) {
                $inventory += [PSCustomObject]@{
                    HostPoolName        = $hpName
                    ResourceGroupName   = $rgName
                    SessionHostName     = $sh.Name.Split('/')[1]
                    Status              = $sh.Status
                    AllowNewSession     = $sh.AllowNewSession
                    AssignedUser        = $sh.AssignedUser
                    Sessions            = $sh.Session
                    LastHeartBeat       = $sh.LastHeartBeat
                    AgentVersion        = $sh.AgentVersion
                    VirtualMachineName  = $sh.ResourceId.Split('/')[-1]
                    UpdateState         = $sh.UpdateState
                    OSVersion           = $sh.OSVersion
                }
            }
        }
    }

    Write-Host "Found $($inventory.Count) session hosts" -ForegroundColor Green

    # Export to CSV
    $inventory | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    
    Write-Host "✓ Inventory exported successfully to: $OutputPath" -ForegroundColor Green
    
    # Display statistics
    $availableCount = ($inventory | Where-Object { $_.Status -eq "Available" }).Count
    $unavailableCount = ($inventory | Where-Object { $_.Status -eq "Unavailable" }).Count
    $needsAssistanceCount = ($inventory | Where-Object { $_.Status -eq "NeedsAssistance" }).Count
    $drainingCount = ($inventory | Where-Object { $_.AllowNewSession -eq $false }).Count
    
    Write-Host "`nSession Host Summary:" -ForegroundColor Cyan
    Write-Host "  Total Session Hosts: $($inventory.Count)" -ForegroundColor White
    Write-Host "  Available: $availableCount" -ForegroundColor Green
    Write-Host "  Unavailable: $unavailableCount" -ForegroundColor Red
    Write-Host "  Needs Assistance: $needsAssistanceCount" -ForegroundColor Yellow
    Write-Host "  Draining Mode: $drainingCount" -ForegroundColor Magenta
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
