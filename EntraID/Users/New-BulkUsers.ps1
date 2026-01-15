<#
.SYNOPSIS
    Creates multiple Entra ID users from a CSV file.

.DESCRIPTION
    This script reads user information from a CSV file and creates new users in Entra ID.
    The CSV should contain columns: DisplayName, UserPrincipalName, MailNickname, 
    Department, JobTitle, UsageLocation.

.PARAMETER CsvPath
    Path to the CSV file containing user information.

.PARAMETER PasswordProfile
    Optional password for all users. If not specified, a random password will be generated.

.PARAMETER ForcePasswordChange
    If specified, users will be required to change password on first sign-in.

.EXAMPLE
    .\New-BulkUsers.ps1 -CsvPath ".\users.csv" -ForcePasswordChange

.EXAMPLE
    .\New-BulkUsers.ps1 -CsvPath ".\users.csv" -PasswordProfile "TempPass@123"

.NOTES
    Requires Microsoft.Graph.Users module and User.ReadWrite.All permissions.
    CSV Format Example:
    DisplayName,UserPrincipalName,MailNickname,Department,JobTitle,UsageLocation
    John Doe,john.doe@contoso.com,johndoe,IT,Systems Administrator,US
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $false)]
    [string]$PasswordProfile,
    
    [Parameter(Mandatory = $false)]
    [switch]$ForcePasswordChange
)

function New-RandomPassword {
    # Use cryptographically secure random number generator
    $length = 16
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] $length
    $rng.GetBytes($bytes)
    
    $password = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    $rng.Dispose()
    return $password
}

try {
    # Check if CSV exists
    if (-not (Test-Path $CsvPath)) {
        throw "CSV file not found: $CsvPath"
    }

    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "User.ReadWrite.All" -NoWelcome
    }

    # Import users from CSV
    $users = Import-Csv -Path $CsvPath
    Write-Host "Found $($users.Count) users in CSV file" -ForegroundColor Cyan

    $successCount = 0
    $failCount = 0
    $results = @()

    foreach ($user in $users) {
        try {
            # Generate or use provided password
            $password = if ($PasswordProfile) { $PasswordProfile } else { New-RandomPassword }
            
            # Create password profile
            $passwordProfileObj = @{
                Password                      = $password
                ForceChangePasswordNextSignIn = $ForcePasswordChange.IsPresent
            }

            # Create user parameters
            $userParams = @{
                AccountEnabled    = $true
                DisplayName       = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                MailNickname      = $user.MailNickname
                PasswordProfile   = $passwordProfileObj
            }

            # Add optional properties if present
            if ($user.Department) { $userParams.Department = $user.Department }
            if ($user.JobTitle) { $userParams.JobTitle = $user.JobTitle }
            if ($user.UsageLocation) { $userParams.UsageLocation = $user.UsageLocation }

            # Create the user
            $newUser = New-MgUser @userParams
            
            Write-Host "✓ Created user: $($user.UserPrincipalName)" -ForegroundColor Green
            
            $results += [PSCustomObject]@{
                DisplayName       = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Status            = "Success"
                Password          = $password
                UserId            = $newUser.Id
            }
            
            $successCount++
        }
        catch {
            Write-Host "✗ Failed to create user: $($user.UserPrincipalName) - $($_.Exception.Message)" -ForegroundColor Red
            
            $results += [PSCustomObject]@{
                DisplayName       = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Status            = "Failed"
                Error             = $_.Exception.Message
            }
            
            $failCount++
        }
    }

    # Export results
    $resultPath = ".\BulkUserCreation_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $results | Export-Csv -Path $resultPath -NoTypeInformation -Encoding UTF8

    Write-Host "`nSummary:" -ForegroundColor Cyan
    Write-Host "  Total Processed: $($users.Count)" -ForegroundColor White
    Write-Host "  Successful: $successCount" -ForegroundColor Green
    Write-Host "  Failed: $failCount" -ForegroundColor Red
    Write-Host "  Results saved to: $resultPath" -ForegroundColor Yellow
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
