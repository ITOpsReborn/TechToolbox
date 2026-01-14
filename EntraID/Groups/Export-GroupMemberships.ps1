<#
.SYNOPSIS
    Exports all Entra ID groups and their members to CSV files.

.DESCRIPTION
    This script exports all groups from Entra ID along with their properties and members.
    Creates two CSV files: one for group details and one for group memberships.

.PARAMETER OutputPath
    The directory path where CSV reports will be saved.

.EXAMPLE
    .\Export-GroupMemberships.ps1 -OutputPath "C:\Reports"

.NOTES
    Requires Microsoft.Graph.Groups module and Group.Read.All permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "."
)

try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "Group.Read.All", "User.Read.All" -NoWelcome
    }

    Write-Host "Retrieving all groups..." -ForegroundColor Cyan
    $groups = Get-MgGroup -All -Property Id, DisplayName, Description, GroupTypes, MailEnabled, SecurityEnabled, CreatedDateTime, MembershipRule

    Write-Host "Found $($groups.Count) groups" -ForegroundColor Green

    $groupDetails = @()
    $memberships = @()

    foreach ($group in $groups) {
        Write-Host "Processing: $($group.DisplayName)" -ForegroundColor Cyan
        
        # Determine group type
        $groupType = if ($group.GroupTypes -contains "Unified") { 
            "Microsoft 365" 
        } elseif ($group.GroupTypes -contains "DynamicMembership") { 
            "Dynamic" 
        } else { 
            "Security" 
        }

        # Get member count
        $members = Get-MgGroupMember -GroupId $group.Id -All
        
        $groupDetails += [PSCustomObject]@{
            DisplayName      = $group.DisplayName
            GroupId          = $group.Id
            Description      = $group.Description
            GroupType        = $groupType
            MailEnabled      = $group.MailEnabled
            SecurityEnabled  = $group.SecurityEnabled
            MemberCount      = $members.Count
            CreatedDateTime  = $group.CreatedDateTime
            MembershipRule   = $group.MembershipRule
        }

        # Export members
        foreach ($member in $members) {
            $memberDetails = Get-MgUser -UserId $member.Id -ErrorAction SilentlyContinue
            if ($memberDetails) {
                $memberships += [PSCustomObject]@{
                    GroupName       = $group.DisplayName
                    GroupId         = $group.Id
                    MemberName      = $memberDetails.DisplayName
                    MemberUPN       = $memberDetails.UserPrincipalName
                    MemberId        = $member.Id
                    MemberType      = "User"
                }
            }
        }
    }

    # Export to CSV
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $groupsFile = Join-Path $OutputPath "EntraID_Groups_$timestamp.csv"
    $membershipsFile = Join-Path $OutputPath "EntraID_GroupMemberships_$timestamp.csv"

    $groupDetails | Export-Csv -Path $groupsFile -NoTypeInformation -Encoding UTF8
    $memberships | Export-Csv -Path $membershipsFile -NoTypeInformation -Encoding UTF8

    Write-Host "`n✓ Export completed successfully!" -ForegroundColor Green
    Write-Host "  Groups: $groupsFile" -ForegroundColor White
    Write-Host "  Memberships: $membershipsFile" -ForegroundColor White
    Write-Host "  Total Groups: $($groupDetails.Count)" -ForegroundColor White
    Write-Host "  Total Memberships: $($memberships.Count)" -ForegroundColor White
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
