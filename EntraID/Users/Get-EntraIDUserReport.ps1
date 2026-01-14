<#
.SYNOPSIS
    Exports a comprehensive report of all Entra ID users.

.DESCRIPTION
    This script retrieves all users from Entra ID and exports detailed information
    including sign-in activity, license assignments, and account status to a CSV file.

.PARAMETER OutputPath
    The path where the CSV report will be saved.

.EXAMPLE
    .\Get-EntraIDUserReport.ps1 -OutputPath "C:\Reports\Users.csv"

.NOTES
    Requires Microsoft.Graph.Users module and User.Read.All permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\EntraID_Users_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    # Check if already connected
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All" -NoWelcome
    }

    Write-Host "Retrieving users from Entra ID..." -ForegroundColor Cyan
    
    # Get all users with relevant properties
    $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Mail, JobTitle, Department, `
        AccountEnabled, CreatedDateTime, SignInActivity, AssignedLicenses, UserType | 
        Select-Object Id, DisplayName, UserPrincipalName, Mail, JobTitle, Department, `
            AccountEnabled, CreatedDateTime, UserType, `
            @{Name = "LastSignInDateTime"; Expression = { $_.SignInActivity.LastSignInDateTime } }, `
            @{Name = "LicenseCount"; Expression = { $_.AssignedLicenses.Count } }

    Write-Host "Found $($users.Count) users" -ForegroundColor Green
    
    # Export to CSV
    $users | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    
    Write-Host "Report exported successfully to: $OutputPath" -ForegroundColor Green
    
    # Display summary statistics
    $enabledCount = ($users | Where-Object { $_.AccountEnabled -eq $true }).Count
    $disabledCount = ($users | Where-Object { $_.AccountEnabled -eq $false }).Count
    $licensedCount = ($users | Where-Object { $_.LicenseCount -gt 0 }).Count
    
    Write-Host "`nSummary:" -ForegroundColor Cyan
    Write-Host "  Total Users: $($users.Count)" -ForegroundColor White
    Write-Host "  Enabled: $enabledCount" -ForegroundColor White
    Write-Host "  Disabled: $disabledCount" -ForegroundColor White
    Write-Host "  Licensed: $licensedCount" -ForegroundColor White
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
