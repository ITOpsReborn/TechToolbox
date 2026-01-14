<#
.SYNOPSIS
    Performs remote actions on Windows 365 Cloud PCs.

.DESCRIPTION
    This script allows you to perform remote actions such as restart, reprovision,
    or end grace period on Cloud PCs.

.PARAMETER UserPrincipalName
    The UPN of the user whose Cloud PC to manage.

.PARAMETER Action
    The action to perform: Restart, Reprovision, or EndGracePeriod.

.PARAMETER CloudPCId
    Optional specific Cloud PC ID to target.

.EXAMPLE
    .\Invoke-CloudPCAction.ps1 -UserPrincipalName "john.doe@contoso.com" -Action Restart

.EXAMPLE
    .\Invoke-CloudPCAction.ps1 -CloudPCId "abc123-def456" -Action Reprovision

.NOTES
    Requires Microsoft.Graph.DeviceManagement.Actions module and CloudPC.ReadWrite.All permissions.
    Reprovision action will rebuild the Cloud PC and may result in data loss.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "ByUser")]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory = $false, ParameterSetName = "ByCloudPCId")]
    [string]$CloudPCId,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Restart", "Reprovision", "EndGracePeriod")]
    [string]$Action
)

try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "CloudPC.ReadWrite.All" -NoWelcome
    }

    # Get target Cloud PC(s)
    if ($UserPrincipalName) {
        Write-Host "Retrieving Cloud PC for user: $UserPrincipalName..." -ForegroundColor Cyan
        $cloudPCs = Get-MgDeviceManagementVirtualEndpointCloudPC -Filter "userPrincipalName eq '$UserPrincipalName'"
    }
    elseif ($CloudPCId) {
        Write-Host "Retrieving Cloud PC with ID: $CloudPCId..." -ForegroundColor Cyan
        $cloudPCs = @(Get-MgDeviceManagementVirtualEndpointCloudPC -CloudPCId $CloudPCId)
    }
    else {
        Write-Error "Please specify either UserPrincipalName or CloudPCId"
        exit 1
    }

    if (-not $cloudPCs -or $cloudPCs.Count -eq 0) {
        Write-Host "No Cloud PCs found matching the criteria." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "Found $($cloudPCs.Count) Cloud PC(s)" -ForegroundColor Green

    # Confirmation for destructive actions
    if ($Action -eq "Reprovision") {
        Write-Host "`nWARNING: Reprovision will rebuild the Cloud PC and may result in data loss!" -ForegroundColor Red
        $confirm = Read-Host "Are you sure you want to continue? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return
        }
    }

    foreach ($pc in $cloudPCs) {
        Write-Host "`nProcessing Cloud PC: $($pc.DisplayName) ($($pc.UserPrincipalName))..." -ForegroundColor Cyan
        
        try {
            switch ($Action) {
                "Restart" {
                    Invoke-MgRestartDeviceManagementVirtualEndpointCloudPC -CloudPCId $pc.Id
                    Write-Host "  ✓ Restart initiated successfully" -ForegroundColor Green
                }
                
                "Reprovision" {
                    Invoke-MgReprovisionDeviceManagementVirtualEndpointCloudPC -CloudPCId $pc.Id
                    Write-Host "  ✓ Reprovision initiated successfully" -ForegroundColor Green
                    Write-Host "  Note: This process may take 30-90 minutes to complete." -ForegroundColor Yellow
                }
                
                "EndGracePeriod" {
                    if ($pc.Status -eq "inGracePeriod") {
                        Stop-MgDeviceManagementVirtualEndpointCloudPCGracePeriod -CloudPCId $pc.Id
                        Write-Host "  ✓ Grace period ended successfully" -ForegroundColor Green
                    }
                    else {
                        Write-Host "  ⚠ Cloud PC is not in grace period (Status: $($pc.Status))" -ForegroundColor Yellow
                    }
                }
            }
        }
        catch {
            Write-Host "  ✗ Failed to perform action: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host "`n✓ Action completed!" -ForegroundColor Green
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
