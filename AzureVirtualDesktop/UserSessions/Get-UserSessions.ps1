<#
.SYNOPSIS
    Gets active user sessions on Azure Virtual Desktop session hosts.

.DESCRIPTION
    This script retrieves all active user sessions across AVD session hosts,
    including session state, connection time, and resource information.

.PARAMETER HostPoolName
    Optional filter for a specific host pool.

.PARAMETER ResourceGroupName
    Optional resource group name (required if HostPoolName is specified).

.PARAMETER OutputPath
    The path where the CSV report will be saved.

.PARAMETER ActiveOnly
    If specified, only returns active (not disconnected) sessions.

.EXAMPLE
    .\Get-UserSessions.ps1 -OutputPath "C:\Reports\UserSessions.csv"

.EXAMPLE
    .\Get-UserSessions.ps1 -HostPoolName "HP-Production" -ResourceGroupName "RG-AVD" -ActiveOnly

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
    [string]$OutputPath = ".\AVD_UserSessions_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$ActiveOnly
)

try {
    Write-Host "Connecting to Azure..." -ForegroundColor Cyan
    
    $context = Get-AzContext
    if (-not $context) {
        Connect-AzAccount
    }

    $allSessions = @()

    if ($HostPoolName -and $ResourceGroupName) {
        Write-Host "Retrieving sessions from host pool: $HostPoolName..." -ForegroundColor Cyan
        $sessionHosts = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName
        
        foreach ($sh in $sessionHosts) {
            $shName = $sh.Name.Split('/')[1]
            $sessions = Get-AzWvdUserSession -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -SessionHostName $shName
            
            foreach ($session in $sessions) {
                $allSessions += [PSCustomObject]@{
                    HostPoolName      = $HostPoolName
                    ResourceGroupName = $ResourceGroupName
                    SessionHostName   = $shName
                    UserPrincipalName = $session.UserPrincipalName
                    SessionState      = $session.SessionState
                    ActiveDirectoryUserName = $session.ActiveDirectoryUserName
                    CreateTime        = $session.CreateTime
                    SessionId         = $session.Name.Split('/')[-1]
                    ApplicationType   = $session.ApplicationType
                }
            }
        }
    }
    else {
        Write-Host "Retrieving all host pools..." -ForegroundColor Cyan
        $hostPools = Get-AzWvdHostPool
        
        foreach ($hp in $hostPools) {
            $hpName = $hp.Name
            $rgName = $hp.Id.Split('/')[4]
            
            Write-Host "  Processing: $hpName..." -ForegroundColor Cyan
            
            $sessionHosts = Get-AzWvdSessionHost -HostPoolName $hpName -ResourceGroupName $rgName
            
            foreach ($sh in $sessionHosts) {
                $shName = $sh.Name.Split('/')[1]
                
                try {
                    $sessions = Get-AzWvdUserSession -HostPoolName $hpName -ResourceGroupName $rgName -SessionHostName $shName -ErrorAction SilentlyContinue
                    
                    foreach ($session in $sessions) {
                        $allSessions += [PSCustomObject]@{
                            HostPoolName      = $hpName
                            ResourceGroupName = $rgName
                            SessionHostName   = $shName
                            UserPrincipalName = $session.UserPrincipalName
                            SessionState      = $session.SessionState
                            ActiveDirectoryUserName = $session.ActiveDirectoryUserName
                            CreateTime        = $session.CreateTime
                            SessionId         = $session.Name.Split('/')[-1]
                            ApplicationType   = $session.ApplicationType
                        }
                    }
                }
                catch {
                    # Session host may not have any sessions
                    continue
                }
            }
        }
    }

    if ($ActiveOnly) {
        $allSessions = $allSessions | Where-Object { $_.SessionState -eq "Active" }
    }

    Write-Host "Found $($allSessions.Count) user sessions" -ForegroundColor Green

    if ($allSessions.Count -gt 0) {
        # Export to CSV
        $allSessions | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "✓ Sessions report exported to: $OutputPath" -ForegroundColor Green
        
        # Display statistics
        $activeCount = ($allSessions | Where-Object { $_.SessionState -eq "Active" }).Count
        $disconnectedCount = ($allSessions | Where-Object { $_.SessionState -eq "Disconnected" }).Count
        $uniqueUsers = ($allSessions | Select-Object -Unique -ExpandProperty UserPrincipalName).Count
        
        Write-Host "`nSession Summary:" -ForegroundColor Cyan
        Write-Host "  Total Sessions: $($allSessions.Count)" -ForegroundColor White
        Write-Host "  Active: $activeCount" -ForegroundColor Green
        Write-Host "  Disconnected: $disconnectedCount" -ForegroundColor Yellow
        Write-Host "  Unique Users: $uniqueUsers" -ForegroundColor White
    }
    else {
        Write-Host "No sessions found." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
