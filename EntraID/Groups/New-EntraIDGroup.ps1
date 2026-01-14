<#
.SYNOPSIS
    Creates a new security group in Entra ID and optionally adds members.

.DESCRIPTION
    This script creates a new security or Microsoft 365 group in Entra ID.
    Supports adding members during creation and setting group properties.

.PARAMETER DisplayName
    The display name of the group.

.PARAMETER MailNickname
    The mail nickname for the group.

.PARAMETER Description
    Optional description of the group.

.PARAMETER GroupType
    Type of group to create: Security or Microsoft365.

.PARAMETER MemberUserPrincipalNames
    Array of user UPNs to add as members.

.EXAMPLE
    .\New-EntraIDGroup.ps1 -DisplayName "IT Team" -MailNickname "itteam" -GroupType Security

.EXAMPLE
    .\New-EntraIDGroup.ps1 -DisplayName "Sales Team" -MailNickname "sales" -GroupType Microsoft365 -MemberUserPrincipalNames @("user1@contoso.com", "user2@contoso.com")

.NOTES
    Requires Microsoft.Graph.Groups module and Group.ReadWrite.All permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,
    
    [Parameter(Mandatory = $true)]
    [string]$MailNickname,
    
    [Parameter(Mandatory = $false)]
    [string]$Description,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Security", "Microsoft365")]
    [string]$GroupType = "Security",
    
    [Parameter(Mandatory = $false)]
    [string[]]$MemberUserPrincipalNames
)

try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "Group.ReadWrite.All", "User.Read.All" -NoWelcome
    }

    # Build group parameters
    $groupParams = @{
        DisplayName     = $DisplayName
        MailNickname    = $MailNickname
        MailEnabled     = ($GroupType -eq "Microsoft365")
        SecurityEnabled = $true
    }

    if ($Description) {
        $groupParams.Description = $Description
    }

    if ($GroupType -eq "Microsoft365") {
        $groupParams.GroupTypes = @("Unified")
    }

    Write-Host "Creating group: $DisplayName..." -ForegroundColor Cyan
    $newGroup = New-MgGroup @groupParams
    
    Write-Host "✓ Group created successfully!" -ForegroundColor Green
    Write-Host "  Group ID: $($newGroup.Id)" -ForegroundColor White
    Write-Host "  Display Name: $($newGroup.DisplayName)" -ForegroundColor White

    # Add members if specified
    if ($MemberUserPrincipalNames) {
        Write-Host "`nAdding members to group..." -ForegroundColor Cyan
        
        foreach ($upn in $MemberUserPrincipalNames) {
            try {
                $user = Get-MgUser -Filter "userPrincipalName eq '$upn'"
                if ($user) {
                    New-MgGroupMember -GroupId $newGroup.Id -DirectoryObjectId $user.Id
                    Write-Host "  ✓ Added: $upn" -ForegroundColor Green
                }
                else {
                    Write-Host "  ✗ User not found: $upn" -ForegroundColor Red
                }
            }
            catch {
                Write-Host "  ✗ Failed to add $upn : $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    Write-Host "`n✓ Group creation completed!" -ForegroundColor Green
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
