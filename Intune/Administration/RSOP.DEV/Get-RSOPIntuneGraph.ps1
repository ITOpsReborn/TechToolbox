<#
.SYNOPSIS
    Intune RSOP with Microsoft Graph API Integration
.DESCRIPTION
    Generates an HTML report showing all Intune policies with actual friendly names from Graph API.
    Retrieves policy display names, application names, and detailed configuration from Microsoft Intune.
    Automatically detects Tenant ID from local machine. Exits if Tenant ID cannot be detected.
.PARAMETER OutputPath
    Path where HTML report will be saved. Defaults to user's Desktop.
.PARAMETER OpenReport
    Automatically open the HTML report after generation.
.EXAMPLE
    .\Get-IntuneRSOP-GraphAPI.ps1 -OpenReport
.EXAMPLE
    .\Get-IntuneRSOP-GraphAPI.ps1 -OutputPath "C:\Reports" -OpenReport
.NOTES
    Requires: Microsoft.Graph.Authentication module
    Permissions needed: DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All, DeviceManagementApps.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    
    [Parameter(Mandatory=$false)]
    [switch]$OpenReport
)

#region Check Admin Rights
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script requires Administrator rights for complete data collection."
    Write-Host "Please run as Administrator." -ForegroundColor Yellow
    exit 1
}
#endregion

#region Get Tenant ID from Local Machine
function Get-LocalTenantId {
    Write-Host "Retrieving Tenant ID from local machine..." -ForegroundColor Cyan
    
    # Method 1: Use dsregcmd (most reliable)
    try {
        $dsregStatus = & dsregcmd /status 2>$null
        
        if ($dsregStatus) {
            $tenantIdLine = $dsregStatus | Select-String "TenantId\s*:\s*([a-f0-9\-]+)" | Select-Object -First 1
            
            if ($tenantIdLine -match "TenantId\s*:\s*([a-f0-9\-]+)") {
                $tenantId = $matches[1].Trim()
                
                if ($tenantId -and $tenantId -ne '' -and $tenantId -match '^[a-f0-9\-]{36}$') {
                    Write-Host "Successfully retrieved Tenant ID from dsregcmd: $tenantId" -ForegroundColor Green
                    return $tenantId
                }
            }
        }
    } catch {
        Write-Verbose "Could not retrieve Tenant ID using dsregcmd: $_"
    }
    
    # Method 2: Check Azure AD join registry
    try {
        $aadPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
        
        if (Test-Path $aadPath) {
            $joinInfo = Get-ChildItem -Path $aadPath -ErrorAction SilentlyContinue | Select-Object -First 1
            
            if ($joinInfo) {
                $props = Get-ItemProperty -Path $joinInfo.PSPath -ErrorAction SilentlyContinue
                
                if ($props.TenantId) {
                    $tenantId = $props.TenantId
                    
                    if ($tenantId -match '^[a-f0-9\-]{36}$') {
                        Write-Host "Successfully retrieved Tenant ID from registry: $tenantId" -ForegroundColor Green
                        return $tenantId
                    }
                }
            }
        }
    } catch {
        Write-Verbose "Could not check Azure AD join registry: $_"
    }
    
    # Method 3: Check Enrollments registry
    try {
        $enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
        
        if (Test-Path $enrollmentPath) {
            $enrollments = Get-ChildItem -Path $enrollmentPath -ErrorAction SilentlyContinue
            
            foreach ($enrollment in $enrollments) {
                $props = Get-ItemProperty -Path $enrollment.PSPath -ErrorAction SilentlyContinue
                
                if ($props.AADTenantID) {
                    $tenantId = $props.AADTenantID
                    
                    if ($tenantId -match '^[a-f0-9\-]{36}$') {
                        Write-Host "Successfully retrieved Tenant ID from enrollments: $tenantId" -ForegroundColor Green
                        return $tenantId
                    }
                }
            }
        }
    } catch {
        Write-Verbose "Could not check enrollments registry: $_"
    }
    
    return $null
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "   Intune RSOP with Microsoft Graph API Integration   " -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# Get Tenant ID from local machine
$detectedTenantId = Get-LocalTenantId

if (-not $detectedTenantId) {
    Write-Host "`n============================================================" -ForegroundColor Red
    Write-Host "   ERROR: Tenant ID Detection Failed" -ForegroundColor Red
    Write-Host "============================================================`n" -ForegroundColor Red
    Write-Host "Could not automatically detect Tenant ID from local machine." -ForegroundColor Yellow
    Write-Host "`nPossible reasons:" -ForegroundColor Yellow
    Write-Host "  1. Device is not Azure AD joined" -ForegroundColor Yellow
    Write-Host "  2. Device is not enrolled in Intune" -ForegroundColor Yellow
    Write-Host "  3. Script is not running with Administrator privileges" -ForegroundColor Yellow
    Write-Host "`nPlease verify:" -ForegroundColor Yellow
    Write-Host "  - Run 'dsregcmd /status' to check Azure AD join status" -ForegroundColor Yellow
    Write-Host "  - Ensure device is properly enrolled in Intune" -ForegroundColor Yellow
    Write-Host "  - Run this script as Administrator`n" -ForegroundColor Yellow
    exit 1
}

Write-Host "Detected Tenant ID: $detectedTenantId`n" -ForegroundColor Green
#endregion

#region Module Check and Graph Connection
Write-Host "Checking Microsoft Graph module..." -ForegroundColor Cyan

$requiredModules = @('Microsoft.Graph.Authentication')

foreach ($module in $requiredModules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing $module..." -ForegroundColor Yellow
        try {
            Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Host "Successfully installed $module" -ForegroundColor Green
        } catch {
            Write-Error "Failed to install $module. Error: $_"
            exit 1
        }
    }
    Import-Module $module -ErrorAction Stop
}

# Connect to Microsoft Graph
Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan

$scopes = @(
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementApps.Read.All",
    "Directory.Read.All"
)

try {
    Write-Host "Connecting to Tenant: $detectedTenantId" -ForegroundColor Cyan
    Connect-MgGraph -Scopes $scopes -TenantId $detectedTenantId -NoWelcome -ErrorAction Stop
    
    $context = Get-MgContext
    Write-Host "Successfully connected to tenant: $($context.TenantId)" -ForegroundColor Green
    Write-Host "Authenticated as: $($context.Account)" -ForegroundColor Green
} catch {
    Write-Host "`n============================================================" -ForegroundColor Red
    Write-Host "   ERROR: Microsoft Graph Connection Failed" -ForegroundColor Red
    Write-Host "============================================================`n" -ForegroundColor Red
    Write-Error "Failed to connect to Microsoft Graph: $_"
    Write-Host "`nPlease ensure you have the required permissions:" -ForegroundColor Yellow
    Write-Host "  - DeviceManagementConfiguration.Read.All" -ForegroundColor Yellow
    Write-Host "  - DeviceManagementManagedDevices.Read.All" -ForegroundColor Yellow
    Write-Host "  - DeviceManagementApps.Read.All" -ForegroundColor Yellow
    Write-Host "  - Directory.Read.All`n" -ForegroundColor Yellow
    exit 1
}
#endregion

#region Helper Functions
function Invoke-MgGraphRequestWithPaging {
    param([string]$Uri)
    
    $allResults = @()
    
    try {
        $response = Invoke-MgGraphRequest -Uri $Uri -Method GET
        
        if ($response.value) {
            $allResults += $response.value
        } else {
            return $response
        }
        
        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET
            $allResults += $response.value
        }
    } catch {
        Write-Verbose "Error retrieving data from $Uri : $_"
    }
    
    return $allResults
}

function Get-IntuneDeviceInfo {
    Write-Host "Collecting device information..." -ForegroundColor Cyan
    
    $deviceInfo = [PSCustomObject]@{
        DeviceName = $env:COMPUTERNAME
        UserName = "$env:USERDOMAIN\$env:USERNAME"
        OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
        OSBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        OSArchitecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        LastBootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        Domain = (Get-CimInstance Win32_ComputerSystem).Domain
        Manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer
        Model = (Get-CimInstance Win32_ComputerSystem).Model
        SerialNumber = (Get-CimInstance Win32_BIOS).SerialNumber
    }
    
    # Get Azure AD Device ID using dsregcmd
    try {
        $dsregStatus = & dsregcmd /status
        $aadDeviceId = ($dsregStatus | Select-String "DeviceId" | Select-Object -First 1) -replace '.*:\s*', ''
        $deviceInfo | Add-Member -NotePropertyName "AzureADDeviceID" -NotePropertyValue $aadDeviceId.Trim()
        
        $tenantId = ($dsregStatus | Select-String "TenantId" | Select-Object -First 1) -replace '.*:\s*', ''
        $deviceInfo | Add-Member -NotePropertyName "TenantID" -NotePropertyValue $tenantId.Trim()
        
        $tenantName = ($dsregStatus | Select-String "TenantName" | Select-Object -First 1) -replace '.*:\s*', ''
        $deviceInfo | Add-Member -NotePropertyName "TenantName" -NotePropertyValue $tenantName.Trim()
        
        $azureAdJoined = ($dsregStatus | Select-String "AzureAdJoined\s*:\s*(\w+)" | Select-Object -First 1)
        if ($azureAdJoined -match "YES") {
            $deviceInfo | Add-Member -NotePropertyName "AzureADJoinStatus" -NotePropertyValue "Yes"
        } else {
            $deviceInfo | Add-Member -NotePropertyName "AzureADJoinStatus" -NotePropertyValue "No"
        }
    } catch {
        $deviceInfo | Add-Member -NotePropertyName "AzureADDeviceID" -NotePropertyValue "Not Available"
        $deviceInfo | Add-Member -NotePropertyName "TenantID" -NotePropertyValue "Not Available"
        $deviceInfo | Add-Member -NotePropertyName "TenantName" -NotePropertyValue "Not Available"
        $deviceInfo | Add-Member -NotePropertyName "AzureADJoinStatus" -NotePropertyValue "Unknown"
    }
    
    # Get Intune Device ID from Graph API
    try {
        Write-Host "Looking up device in Intune..." -ForegroundColor Cyan
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=deviceName eq '$($env:COMPUTERNAME)'"
        $intuneDevice = Invoke-MgGraphRequestWithPaging -Uri $uri
        
        if ($intuneDevice -and $intuneDevice.Count -gt 0) {
            $deviceInfo | Add-Member -NotePropertyName "IntuneDeviceID" -NotePropertyValue $intuneDevice[0].id
            $deviceInfo | Add-Member -NotePropertyName "IntuneDeviceName" -NotePropertyValue $intuneDevice[0].deviceName
            $deviceInfo | Add-Member -NotePropertyName "ManagementState" -NotePropertyValue $intuneDevice[0].managementState
            $deviceInfo | Add-Member -NotePropertyName "ComplianceState" -NotePropertyValue $intuneDevice[0].complianceState
            $deviceInfo | Add-Member -NotePropertyName "LastSyncDateTime" -NotePropertyValue $intuneDevice[0].lastSyncDateTime
            $deviceInfo | Add-Member -NotePropertyName "IntuneDeviceObject" -NotePropertyValue $intuneDevice[0]
            Write-Host "Device found in Intune: $($intuneDevice[0].deviceName)" -ForegroundColor Green
        } else {
            Write-Warning "Device not found in Intune"
            $deviceInfo | Add-Member -NotePropertyName "IntuneDeviceID" -NotePropertyValue "Not Found"
            $deviceInfo | Add-Member -NotePropertyName "ManagementState" -NotePropertyValue "Unknown"
            $deviceInfo | Add-Member -NotePropertyName "ComplianceState" -NotePropertyValue "Unknown"
            $deviceInfo | Add-Member -NotePropertyName "LastSyncDateTime" -NotePropertyValue "N/A"
        }
    } catch {
        Write-Warning "Could not retrieve device from Intune: $_"
        $deviceInfo | Add-Member -NotePropertyName "IntuneDeviceID" -NotePropertyValue "Error"
        $deviceInfo | Add-Member -NotePropertyName "ManagementState" -NotePropertyValue "Unknown"
        $deviceInfo | Add-Member -NotePropertyName "ComplianceState" -NotePropertyValue "Unknown"
        $deviceInfo | Add-Member -NotePropertyName "LastSyncDateTime" -NotePropertyValue "N/A"
    }
    
    # Check local enrollment status
    $enrollmentKeys = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Enrollments" -ErrorAction SilentlyContinue
    if ($enrollmentKeys) {
        $deviceInfo | Add-Member -NotePropertyName "MDMEnrollmentStatus" -NotePropertyValue "Enrolled"
        $deviceInfo | Add-Member -NotePropertyName "EnrollmentCount" -NotePropertyValue $enrollmentKeys.Count
    } else {
        $deviceInfo | Add-Member -NotePropertyName "MDMEnrollmentStatus" -NotePropertyValue "Not Enrolled"
        $deviceInfo | Add-Member -NotePropertyName "EnrollmentCount" -NotePropertyValue 0
    }
    
    return $deviceInfo
}

function Get-IntunePoliciesFromGraph {
    Write-Host "Retrieving all Intune policies from Graph API..." -ForegroundColor Cyan
    
    $allPolicies = @()
    
    # Device Configuration Profiles
    Write-Host "  - Device Configuration Profiles..." -ForegroundColor Gray
    try {
        $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
        $configs = Invoke-MgGraphRequestWithPaging -Uri $uri
        
        foreach ($config in $configs) {
            $allPolicies += [PSCustomObject]@{
                PolicyID = $config.id
                PolicyName = $config.displayName
                PolicyType = "Device Configuration"
                ODataType = $config.'@odata.type'
                Description = $config.description
                LastModified = $config.lastModifiedDateTime
            }
        }
        Write-Host "    Found $($configs.Count) device configurations" -ForegroundColor Green
    } catch {
        Write-Warning "Could not retrieve device configurations: $_"
    }
    
    # Settings Catalog Policies
    Write-Host "  - Settings Catalog Policies..." -ForegroundColor Gray
    try {
        $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
        $catalogPolicies = Invoke-MgGraphRequestWithPaging -Uri $uri
        
        foreach ($policy in $catalogPolicies) {
            $allPolicies += [PSCustomObject]@{
                PolicyID = $policy.id
                PolicyName = $policy.name
                PolicyType = "Settings Catalog"
                ODataType = "Settings Catalog"
                Description = $policy.description
                LastModified = $policy.lastModifiedDateTime
            }
        }
        Write-Host "    Found $($catalogPolicies.Count) settings catalog policies" -ForegroundColor Green
    } catch {
        Write-Warning "Could not retrieve settings catalog policies: $_"
    }
    
    # Compliance Policies
    Write-Host "  - Compliance Policies..." -ForegroundColor Gray
    try {
        $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
        $compliancePolicies = Invoke-MgGraphRequestWithPaging -Uri $uri
        
        foreach ($policy in $compliancePolicies) {
            $allPolicies += [PSCustomObject]@{
                PolicyID = $policy.id
                PolicyName = $policy.displayName
                PolicyType = "Compliance Policy"
                ODataType = $policy.'@odata.type'
                Description = $policy.description
                LastModified = $policy.lastModifiedDateTime
            }
        }
        Write-Host "    Found $($compliancePolicies.Count) compliance policies" -ForegroundColor Green
    } catch {
        Write-Warning "Could not retrieve compliance policies: $_"
    }
    
    # Endpoint Security Policies
    Write-Host "  - Endpoint Security Policies..." -ForegroundColor Gray
    try {
        $uri = "https://graph.microsoft.com/beta/deviceManagement/intents"
        $intents = Invoke-MgGraphRequestWithPaging -Uri $uri
        
        foreach ($intent in $intents) {
            $allPolicies += [PSCustomObject]@{
                PolicyID = $intent.id
                PolicyName = $intent.displayName
                PolicyType = "Endpoint Security"
                ODataType = $intent.templateId
                Description = $intent.description
                LastModified = $intent.lastModifiedDateTime
            }
        }
        Write-Host "    Found $($intents.Count) endpoint security policies" -ForegroundColor Green
    } catch {
        Write-Warning "Could not retrieve endpoint security policies: $_"
    }
    
    # App Configuration Policies
    Write-Host "  - App Configuration Policies..." -ForegroundColor Gray
    try {
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations"
        $appConfigs = Invoke-MgGraphRequestWithPaging -Uri $uri
        
        foreach ($config in $appConfigs) {
            $allPolicies += [PSCustomObject]@{
                PolicyID = $config.id
                PolicyName = $config.displayName
                PolicyType = "App Configuration"
                ODataType = $config.'@odata.type'
                Description = $config.description
                LastModified = $config.lastModifiedDateTime
            }
        }
        Write-Host "    Found $($appConfigs.Count) app configuration policies" -ForegroundColor Green
    } catch {
        Write-Warning "Could not retrieve app configuration policies: $_"
    }
    
    # App Protection Policies
    Write-Host "  - App Protection Policies..." -ForegroundColor Gray
    try {
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies"
        $appProtectionPolicies = Invoke-MgGraphRequestWithPaging -Uri $uri
        
        foreach ($policy in $appProtectionPolicies) {
            $allPolicies += [PSCustomObject]@{
                PolicyID = $policy.id
                PolicyName = $policy.displayName
                PolicyType = "App Protection"
                ODataType = $policy.'@odata.type'
                Description = $policy.description
                LastModified = $policy.lastModifiedDateTime
            }
        }
        Write-Host "    Found $($appProtectionPolicies.Count) app protection policies" -ForegroundColor Green
    } catch {
        Write-Warning "Could not retrieve app protection policies: $_"
    }
    
    Write-Host "Total policies retrieved from Graph: $($allPolicies.Count)" -ForegroundColor Green
    return $allPolicies
}

function Get-IntuneApplicationsFromGraph {
    Write-Host "Retrieving Intune applications from Graph API..." -ForegroundColor Cyan
    
    $apps = @()
    
    try {
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true"
        $mobileApps = Invoke-MgGraphRequestWithPaging -Uri $uri
        
        foreach ($app in $mobileApps) {
            $apps += [PSCustomObject]@{
                AppID = $app.id
                AppName = $app.displayName
                AppType = $app.'@odata.type' -replace '#microsoft.graph.', ''
                Publisher = $app.publisher
                Description = $app.description
                CreatedDateTime = $app.createdDateTime
                LastModifiedDateTime = $app.lastModifiedDateTime
            }
        }
        
        Write-Host "Found $($apps.Count) assigned applications" -ForegroundColor Green
    } catch {
        Write-Warning "Could not retrieve applications: $_"
    }
    
    return $apps
}

function Get-LocalMDMPolicies {
    Write-Host "Reading local MDM registry policies..." -ForegroundColor Cyan
    
    $localPolicies = @()
    $currentPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device"
    
    if (Test-Path $currentPath) {
        $policyAreas = Get-ChildItem -Path $currentPath -ErrorAction SilentlyContinue
        
        foreach ($area in $policyAreas) {
            $areaName = $area.PSChildName
            
            try {
                $properties = Get-ItemProperty -Path $area.PSPath -ErrorAction SilentlyContinue
                
                foreach ($prop in $properties.PSObject.Properties) {
                    if ($prop.Name -notmatch "^PS" -and $prop.Value) {
                        $localPolicies += [PSCustomObject]@{
                            Area = $areaName
                            Setting = $prop.Name
                            Value = $prop.Value
                            Path = $area.PSPath
                        }
                    }
                }
            } catch {
                Write-Verbose "Could not read area: $areaName"
            }
        }
    }
    
    Write-Host "Found $($localPolicies.Count) local policy settings" -ForegroundColor Green
    return $localPolicies
}

function Get-DevicePolicyAssignments {
    param(
        [string]$DeviceId,
        [array]$AllPolicies
    )
    
    Write-Host "Checking policy assignments for this device..." -ForegroundColor Cyan
    
    $assignedPolicies = @()
    $counter = 0
    
    foreach ($policy in $AllPolicies) {
        $counter++
        if ($counter % 10 -eq 0) {
            Write-Host "  Processed $counter of $($AllPolicies.Count) policies..." -ForegroundColor Gray
        }
        
        try {
            $uri = $null
            
            switch ($policy.PolicyType) {
                "Device Configuration" {
                    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($policy.PolicyID)/assignments"
                }
                "Settings Catalog" {
                    $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($policy.PolicyID)/assignments"
                }
                "Compliance Policy" {
                    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($policy.PolicyID)/assignments"
                }
                "Endpoint Security" {
                    $uri = "https://graph.microsoft.com/beta/deviceManagement/intents/$($policy.PolicyID)/assignments"
                }
                "App Configuration" {
                    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations/$($policy.PolicyID)/assignments"
                }
            }
            
            if ($uri) {
                $assignments = Invoke-MgGraphRequestWithPaging -Uri $uri
                
                if ($assignments -and $assignments.Count -gt 0) {
                    $assignedPolicies += [PSCustomObject]@{
                        PolicyID = $policy.PolicyID
                        PolicyName = $policy.PolicyName
                        PolicyType = $policy.PolicyType
                        Description = $policy.Description
                        AssignmentCount = $assignments.Count
                        IsAssigned = $true
                    }
                }
            }
        } catch {
            Write-Verbose "Could not check assignments for policy: $($policy.PolicyName)"
        }
    }
    
    Write-Host "Device has $($assignedPolicies.Count) policies with assignments" -ForegroundColor Green
    return $assignedPolicies
}

function Get-LocalInstalledApplications {
    Write-Host "Reading locally installed applications..." -ForegroundColor Cyan
    
    $apps = @()
    $win32AppPath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
    
    if (Test-Path $win32AppPath) {
        $userSIDs = Get-ChildItem -Path $win32AppPath -ErrorAction SilentlyContinue
        
        foreach ($sid in $userSIDs) {
            $appGUIDs = Get-ChildItem -Path $sid.PSPath -ErrorAction SilentlyContinue
            
            foreach ($appGUID in $appGUIDs) {
                $appProps = Get-ItemProperty -Path $appGUID.PSPath -ErrorAction SilentlyContinue
                
                $apps += [PSCustomObject]@{
                    AppGUID = $appGUID.PSChildName
                    UserSID = $sid.PSChildName
                    InstallState = $appProps.InstallState
                    ComplianceState = $appProps.ComplianceState
                    EnforcementState = $appProps.EnforcementState
                    LastUpdateTime = $appProps.LastUpdateTimeUtc
                }
            }
        }
    }
    
    Write-Host "Found $($apps.Count) Intune-deployed applications locally" -ForegroundColor Green
    return $apps
}

function Resolve-ApplicationNames {
    param(
        [array]$LocalApps,
        [array]$GraphApps
    )
    
    Write-Host "Matching local applications with Graph API names..." -ForegroundColor Cyan
    
    $resolvedApps = @()
    
    foreach ($localApp in $LocalApps) {
        $graphApp = $GraphApps | Where-Object { $_.AppID -eq $localApp.AppGUID }
        
        $installStateText = switch ($localApp.InstallState) {
            1 { "Installed" }
            2 { "Not Installed" }
            3 { "Installing" }
            4 { "Uninstalling" }
            5 { "Failed" }
            default { "Unknown ($($localApp.InstallState))" }
        }
        
        $complianceStateText = switch ($localApp.ComplianceState) {
            0 { "Unknown" }
            1 { "Compliant" }
            2 { "Not Compliant" }
            3 { "In Grace Period" }
            default { "Unknown ($($localApp.ComplianceState))" }
        }
        
        $resolvedApps += [PSCustomObject]@{
            AppName = if ($graphApp) { $graphApp.AppName } else { "Unknown App" }
            AppGUID = $localApp.AppGUID
            AppType = if ($graphApp) { $graphApp.AppType } else { "Unknown" }
            Publisher = if ($graphApp) { $graphApp.Publisher } else { "Unknown" }
            InstallState = $installStateText
            ComplianceState = $complianceStateText
            LastUpdateTime = $localApp.LastUpdateTime
        }
    }
    
    return $resolvedApps
}

function Get-IntuneCertificates {
    Write-Host "Collecting Intune-deployed certificates..." -ForegroundColor Cyan
    
    $certs = @()
    $stores = @("Cert:\LocalMachine\My", "Cert:\CurrentUser\My", "Cert:\LocalMachine\Root")
    
    foreach ($store in $stores) {
        try {
            $certificates = Get-ChildItem -Path $store -ErrorAction SilentlyContinue | 
                Where-Object { 
                    $_.Issuer -match "Intune|Microsoft|MDM|CloudDM" -or 
                    $_.Subject -match "Intune|Microsoft|MDM"
                }
            
            foreach ($cert in $certificates) {
                $certs += [PSCustomObject]@{
                    Store = $store -replace "Cert:\\", ""
                    Subject = $cert.Subject
                    Issuer = $cert.Issuer
                    Thumbprint = $cert.Thumbprint
                    NotBefore = $cert.NotBefore
                    NotAfter = $cert.NotAfter
                    DaysUntilExpiry = ([int]($cert.NotAfter - (Get-Date)).TotalDays)
                    HasPrivateKey = $cert.HasPrivateKey
                }
            }
        } catch {
            Write-Verbose "Could not access store: $store"
        }
    }
    
    return $certs
}

function Get-EnrollmentDetails {
    Write-Host "Collecting enrollment details..." -ForegroundColor Cyan
    
    $enrollments = @()
    $enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
    
    if (Test-Path $enrollmentPath) {
        $enrollmentGUIDs = Get-ChildItem -Path $enrollmentPath -ErrorAction SilentlyContinue
        
        foreach ($guid in $enrollmentGUIDs) {
            $props = Get-ItemProperty -Path $guid.PSPath -ErrorAction SilentlyContinue
            
            $enrollments += [PSCustomObject]@{
                EnrollmentGUID = $guid.PSChildName
                ProviderID = $props.ProviderID
                UPN = $props.UPN
                EnrollmentType = switch ($props.EnrollmentType) {
                    0 { "Device" }
                    4 { "Azure AD Joined" }
                    6 { "MDM with Azure AD" }
                    13 { "Azure AD Join with enrollment" }
                    default { "Unknown ($($props.EnrollmentType))" }
                }
                EnrollmentState = switch ($props.EnrollmentState) {
                    1 { "Enrolled" }
                    2 { "Failed" }
                    3 { "Pending" }
                    default { "Unknown ($($props.EnrollmentState))" }
                }
                AADDeviceID = $props.AADDeviceID
                DMPServerURL = $props.DiscoveryServiceFullURL
            }
        }
    }
    
    return $enrollments
}

function Decode-PolicyValue {
    param($Value)
    
    if ($Value -eq 0 -or $Value -eq '0' -or $Value -eq $false) {
        return "Disabled / No / False"
    }
    
    if ($Value -eq 1 -or $Value -eq '1' -or $Value -eq $true) {
        return "Enabled / Yes / True"
    }
    
    if ($Value -match '<enabled/>') {
        if ($Value -match 'data id="([^"]+)"\s+value="([^"]+)"') {
            $matches = [regex]::Matches($Value, 'data id="([^"]+)"\s+value="([^"]+)"')
            $xmlData = @()
            foreach ($match in $matches) {
                $xmlData += "$($match.Groups[1].Value) = $($match.Groups[2].Value)"
            }
            if ($xmlData.Count -gt 0) {
                return "Enabled: " + ($xmlData -join '; ')
            }
        }
        return "Enabled"
    }
    
    if ($Value.ToString().Length -gt 150) {
        return $Value.ToString().Substring(0, 147) + "..."
    }
    
    return $Value
}

function Generate-HTMLReport {
    param(
        [object]$DeviceInfo,
        [array]$LocalPolicies,
        [array]$GraphPolicies,
        [array]$AssignedPolicies,
        [array]$Applications,
        [array]$Certificates,
        [array]$Enrollments,
        [string]$OutputFile
    )
    
    Write-Host "Generating comprehensive HTML report..." -ForegroundColor Cyan
    
    $groupedPolicies = $LocalPolicies | Group-Object -Property Area
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Intune RSOP Report - $($DeviceInfo.DeviceName)</title>
    <meta charset="UTF-8">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body { 
            font-family: Arial, Helvetica, sans-serif;
            margin: 0;
            padding: 20px; 
            background-color: #f0f0f0;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }
        
        h1 { 
            color: #0078d4; 
            border-bottom: 3px solid #0078d4; 
            padding-bottom: 15px;
            margin-bottom: 20px;
            font-size: 28px;
        }
        
        h2 { 
            color: #106ebe; 
            margin-top: 30px;
            margin-bottom: 15px;
            font-size: 20px;
            padding-left: 10px;
            border-left: 5px solid #0078d4;
        }
        
        .metadata {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            color: #666;
            font-size: 14px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 25px 0;
        }
        
        .summary-card {
            background-color: #0078d4;
            color: white;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
        }
        
        .summary-card h3 {
            font-size: 13px;
            margin-bottom: 10px;
            opacity: 0.9;
            font-weight: normal;
        }
        
        .summary-card .value {
            font-size: 36px;
            font-weight: bold;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 12px;
            margin: 20px 0;
        }
        
        .info-item {
            background-color: #f8f9fa;
            padding: 12px;
            border-radius: 5px;
            border-left: 3px solid #0078d4;
        }
        
        .info-item strong {
            display: block;
            color: #106ebe;
            font-size: 11px;
            margin-bottom: 4px;
            text-transform: uppercase;
        }
        
        .info-item span {
            color: #333;
            font-size: 14px;
            word-break: break-all;
        }
        
        .collapsible {
            background-color: #106ebe;
            color: white;
            cursor: pointer;
            padding: 15px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 15px;
            margin-top: 10px;
            border-radius: 5px;
            font-weight: bold;
            transition: background-color 0.3s;
        }
        
        .collapsible:hover {
            background-color: #0078d4;
        }
        
        .collapsible:after {
            content: '+';
            color: white;
            font-weight: bold;
            float: right;
            font-size: 18px;
        }
        
        .collapsible.active:after {
            content: '-';
        }
        
        .content {
            padding: 0;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
            background-color: white;
        }
        
        .content.active {
            padding: 20px 10px;
            max-height: 10000px;
        }
        
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin: 15px 0;
            background-color: white;
            border: 1px solid #ddd;
        }
        
        th { 
            background-color: #0078d4;
            color: white; 
            padding: 12px; 
            text-align: left;
            font-weight: bold;
            font-size: 13px;
        }
        
        td { 
            padding: 10px; 
            border-bottom: 1px solid #e0e0e0;
            font-size: 13px;
        }
        
        tr:hover { 
            background-color: #f5f5f5;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        .status-success { 
            color: #107c10; 
            font-weight: bold;
            background-color: #dff6dd;
            padding: 3px 10px;
            border-radius: 10px;
            display: inline-block;
            font-size: 12px;
        }
        
        .status-warning { 
            color: #ca5010; 
            font-weight: bold;
            background-color: #fff4ce;
            padding: 3px 10px;
            border-radius: 10px;
            display: inline-block;
            font-size: 12px;
        }
        
        .status-error { 
            color: #d13438; 
            font-weight: bold;
            background-color: #fde7e9;
            padding: 3px 10px;
            border-radius: 10px;
            display: inline-block;
            font-size: 12px;
        }
        
        .policy-section {
            margin: 20px 0;
            padding: 15px;
            background-color: #fafafa;
            border-radius: 5px;
            border: 1px solid #e0e0e0;
        }
        
        .policy-header {
            color: #0078d4;
            font-weight: bold;
            font-size: 16px;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 2px solid #0078d4;
        }
        
        .policy-item {
            background-color: white;
            padding: 10px;
            margin: 8px 0;
            border-radius: 4px;
            border-left: 3px solid #0078d4;
        }
        
        .policy-name {
            font-weight: bold;
            color: #333;
            margin-bottom: 4px;
        }
        
        .policy-value {
            color: #0078d4;
            font-size: 13px;
        }
        
        .footer {
            margin-top: 40px;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 5px;
            text-align: center;
            color: #666;
            font-size: 13px;
            border-top: 3px solid #0078d4;
        }
        
        .search-box {
            width: 100%;
            padding: 12px;
            margin: 15px 0;
            border: 2px solid #0078d4;
            border-radius: 5px;
            font-size: 14px;
            font-family: Arial, Helvetica, sans-serif;
        }
        
        .code {
            font-family: Consolas, Monaco, monospace;
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
            color: #333;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>Intune RSOP Report</h1>
    <div class="metadata">
        <strong>Report Generated:</strong> $(Get-Date -Format "dddd, MMMM dd, yyyy 'at' hh:mm:ss tt")<br>
        <strong>Tenant:</strong> $($DeviceInfo.TenantName) ($($DeviceInfo.TenantID))
    </div>
    
    <button type="button" class="collapsible">Summary Statistics</button>
    <div class="content">
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Local Policy Settings</h3>
                <p class="value">$($LocalPolicies.Count)</p>
            </div>
            <div class="summary-card">
                <h3>Graph Policies</h3>
                <p class="value">$($GraphPolicies.Count)</p>
            </div>
            <div class="summary-card">
                <h3>Applications</h3>
                <p class="value">$($Applications.Count)</p>
            </div>
            <div class="summary-card">
                <h3>Certificates</h3>
                <p class="value">$($Certificates.Count)</p>
            </div>
        </div>
    </div>
    
    <button type="button" class="collapsible">Device Information</button>
    <div class="content">
        <div class="info-grid">
            <div class="info-item"><strong>Device Name</strong><span>$($DeviceInfo.DeviceName)</span></div>
            <div class="info-item"><strong>User</strong><span>$($DeviceInfo.UserName)</span></div>
            <div class="info-item"><strong>OS Version</strong><span>$($DeviceInfo.OSVersion)</span></div>
            <div class="info-item"><strong>OS Build</strong><span>$($DeviceInfo.OSBuild)</span></div>
            <div class="info-item"><strong>Architecture</strong><span>$($DeviceInfo.OSArchitecture)</span></div>
            <div class="info-item"><strong>Last Boot Time</strong><span>$($DeviceInfo.LastBootTime.ToString("yyyy-MM-dd HH:mm:ss"))</span></div>
            <div class="info-item"><strong>Domain</strong><span>$($DeviceInfo.Domain)</span></div>
            <div class="info-item"><strong>Manufacturer</strong><span>$($DeviceInfo.Manufacturer)</span></div>
            <div class="info-item"><strong>Model</strong><span>$($DeviceInfo.Model)</span></div>
            <div class="info-item"><strong>Serial Number</strong><span>$($DeviceInfo.SerialNumber)</span></div>
            <div class="info-item"><strong>Intune Device ID</strong><span class="code">$($DeviceInfo.IntuneDeviceID)</span></div>
            <div class="info-item"><strong>Azure AD Device ID</strong><span class="code">$($DeviceInfo.AzureADDeviceID)</span></div>
            <div class="info-item"><strong>Management State</strong><span>$($DeviceInfo.ManagementState)</span></div>
            <div class="info-item"><strong>Compliance State</strong><span>$($DeviceInfo.ComplianceState)</span></div>
            <div class="info-item"><strong>Last Sync</strong><span>$($DeviceInfo.LastSyncDateTime)</span></div>
            <div class="info-item"><strong>MDM Enrollment</strong><span class="status-success">$($DeviceInfo.MDMEnrollmentStatus)</span></div>
        </div>
    </div>
    
    <button type="button" class="collapsible">Enrollment Details ($($Enrollments.Count))</button>
    <div class="content">
        <table>
            <tr>
                <th>Enrollment GUID</th>
                <th>Provider ID</th>
                <th>UPN</th>
                <th>Enrollment Type</th>
                <th>State</th>
            </tr>
"@
    
    foreach ($enrollment in $Enrollments) {
        $htmlReport += @"
            <tr>
                <td><span class="code">$($enrollment.EnrollmentGUID)</span></td>
                <td>$($enrollment.ProviderID)</td>
                <td>$($enrollment.UPN)</td>
                <td>$($enrollment.EnrollmentType)</td>
                <td>$($enrollment.EnrollmentState)</td>
            </tr>
"@
    }
    
    $htmlReport += @"
        </table>
    </div>
    
    <button type="button" class="collapsible">Assigned Policies from Intune ($($AssignedPolicies.Count))</button>
    <div class="content">
        <input type="text" id="policySearch" class="search-box" placeholder="Search policies by name or type..." onkeyup="filterTable('policySearch', 'policyTable')">
        <table id="policyTable">
            <tr>
                <th>Policy Name</th>
                <th>Policy Type</th>
                <th>Description</th>
                <th>Assignments</th>
            </tr>
"@
    
    foreach ($policy in ($AssignedPolicies | Sort-Object PolicyType, PolicyName)) {
        $htmlReport += @"
            <tr>
                <td><strong>$($policy.PolicyName)</strong></td>
                <td>$($policy.PolicyType)</td>
                <td>$($policy.Description)</td>
                <td>$($policy.AssignmentCount) group(s)</td>
            </tr>
"@
    }
    
    $htmlReport += @"
        </table>
    </div>
    
    <button type="button" class="collapsible">Local Applied Policy Settings ($($LocalPolicies.Count))</button>
    <div class="content">
        <input type="text" id="localPolicySearch" class="search-box" placeholder="Search local settings..." onkeyup="filterPolicySections()">
        <div id="localPoliciesContainer">
"@
    
    foreach ($group in ($groupedPolicies | Sort-Object Name)) {
        $htmlReport += @"
        <div class="policy-section policy-group">
            <div class="policy-header">$($group.Name) ($($group.Group.Count) settings)</div>
"@
        
        foreach ($policy in ($group.Group | Sort-Object Setting)) {
            $decodedValue = Decode-PolicyValue -Value $policy.Value
            
            $htmlReport += @"
            <div class="policy-item">
                <div class="policy-name">$($policy.Setting)</div>
                <div class="policy-value">$decodedValue</div>
            </div>
"@
        }
        
        $htmlReport += @"
        </div>
"@
    }
    
    $htmlReport += @"
        </div>
    </div>
    
    <button type="button" class="collapsible">Applications ($($Applications.Count))</button>
    <div class="content">
        <table>
            <tr>
                <th>Application Name</th>
                <th>Publisher</th>
                <th>Type</th>
                <th>Install State</th>
                <th>Compliance State</th>
                <th>Last Update</th>
            </tr>
"@
    
    foreach ($app in ($Applications | Sort-Object AppName)) {
        $stateClass = switch ($app.InstallState) {
            "Installed" { "status-success" }
            "Failed" { "status-error" }
            default { "status-warning" }
        }
        
        $htmlReport += @"
            <tr>
                <td><strong>$($app.AppName)</strong></td>
                <td>$($app.Publisher)</td>
                <td>$($app.AppType)</td>
                <td><span class="$stateClass">$($app.InstallState)</span></td>
                <td>$($app.ComplianceState)</td>
                <td>$($app.LastUpdateTime)</td>
            </tr>
"@
    }
    
    $htmlReport += @"
        </table>
    </div>
    
    <button type="button" class="collapsible">Certificates ($($Certificates.Count))</button>
    <div class="content">
        <table>
            <tr>
                <th>Store</th>
                <th>Subject</th>
                <th>Issuer</th>
                <th>Valid Until</th>
                <th>Days Remaining</th>
                <th>Private Key</th>
            </tr>
"@
    
    foreach ($cert in ($Certificates | Sort-Object DaysUntilExpiry)) {
        $daysClass = if ($cert.DaysUntilExpiry -lt 30) { "status-error" } 
                     elseif ($cert.DaysUntilExpiry -lt 90) { "status-warning" } 
                     else { "status-success" }
        
        $htmlReport += @"
            <tr>
                <td>$($cert.Store)</td>
                <td>$($cert.Subject)</td>
                <td>$($cert.Issuer)</td>
                <td>$($cert.NotAfter.ToString("yyyy-MM-dd"))</td>
                <td><span class="$daysClass">$($cert.DaysUntilExpiry) days</span></td>
                <td>$($cert.HasPrivateKey)</td>
            </tr>
"@
    }
    
    $htmlReport += @"
        </table>
    </div>
    
    <button type="button" class="collapsible">All Policies in Tenant ($($GraphPolicies.Count))</button>
    <div class="content">
        <input type="text" id="allPolicySearch" class="search-box" placeholder="Search all tenant policies..." onkeyup="filterTable('allPolicySearch', 'allPolicyTable')">
        <table id="allPolicyTable">
            <tr>
                <th>Policy Name</th>
                <th>Policy Type</th>
                <th>Description</th>
                <th>Last Modified</th>
            </tr>
"@
    
    foreach ($policy in ($GraphPolicies | Sort-Object PolicyType, PolicyName)) {
        $htmlReport += @"
            <tr>
                <td><strong>$($policy.PolicyName)</strong></td>
                <td>$($policy.PolicyType)</td>
                <td>$($policy.Description)</td>
                <td>$($policy.LastModified)</td>
            </tr>
"@
    }
    
    $htmlReport += @"
        </table>
    </div>
    
    <div class="footer">
        <h3 style="color: #0078d4; margin-bottom: 10px;">Intune RSOP Report</h3>
        <p>Generated on <strong>$($DeviceInfo.DeviceName)</strong> using Microsoft Graph API</p>
        <p>PowerShell Version: <strong>$($PSVersionTable.PSVersion)</strong></p>
        <p style="margin-top: 10px; font-size: 12px;">This report displays the Resultant Set of Policies applied to this device through Microsoft Intune</p>
    </div>
</div>

<script>
    // Collapsible sections
    var coll = document.getElementsByClassName("collapsible");
    for (var i = 0; i < coll.length; i++) {
        coll[i].addEventListener("click", function() {
            this.classList.toggle("active");
            var content = this.nextElementSibling;
            content.classList.toggle("active");
        });
    }
    
    // Table filter function
    function filterTable(searchId, tableId) {
        var input = document.getElementById(searchId);
        var filter = input.value.toUpperCase();
        var table = document.getElementById(tableId);
        var tr = table.getElementsByTagName("tr");
        
        for (var i = 1; i < tr.length; i++) {
            var row = tr[i];
            var txtValue = row.textContent || row.innerText;
            
            if (txtValue.toUpperCase().indexOf(filter) > -1) {
                row.style.display = "";
            } else {
                row.style.display = "none";
            }
        }
    }
    
    // Policy sections filter
    function filterPolicySections() {
        var input = document.getElementById("localPolicySearch");
        var filter = input.value.toUpperCase();
        var sections = document.getElementsByClassName("policy-group");
        
        for (var i = 0; i < sections.length; i++) {
            var section = sections[i];
            var items = section.getElementsByClassName("policy-item");
            var visibleCount = 0;
            
            for (var j = 0; j < items.length; j++) {
                var item = items[j];
                var txtValue = item.textContent || item.innerText;
                
                if (txtValue.toUpperCase().indexOf(filter) > -1) {
                    item.style.display = "";
                    visibleCount++;
                } else {
                    item.style.display = "none";
                }
            }
            
            if (visibleCount > 0 || filter === "") {
                section.style.display = "";
            } else {
                section.style.display = "none";
            }
        }
    }
    
    // Auto-expand first section
    if (coll.length > 0) {
        coll[0].click();
    }
</script>
</body>
</html>
"@
    
    $htmlReport | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "HTML report saved to: $OutputFile" -ForegroundColor Green
}
#endregion

#region Main Execution
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "IntuneRSOP_GraphAPI_$env:COMPUTERNAME`_$timestamp.html"

# Step 1: Collect device information
$deviceInfo = Get-IntuneDeviceInfo

if ($deviceInfo.IntuneDeviceID -eq "Not Found") {
    Write-Warning "Device not found in Intune. Report will include limited information."
}

# Step 2: Get all policies from Graph API
$graphPolicies = Get-IntunePoliciesFromGraph

# Step 3: Get policy assignments for this device
$assignedPolicies = @()
if ($deviceInfo.IntuneDeviceID -and $deviceInfo.IntuneDeviceID -ne "Not Found") {
    $assignedPolicies = Get-DevicePolicyAssignments -DeviceId $deviceInfo.IntuneDeviceID -AllPolicies $graphPolicies
}

# Step 4: Get local MDM policies from registry
$localPolicies = Get-LocalMDMPolicies

# Step 5: Get applications from Graph and local
$graphApps = Get-IntuneApplicationsFromGraph
$localApps = Get-LocalInstalledApplications
$resolvedApps = Resolve-ApplicationNames -LocalApps $localApps -GraphApps $graphApps

# Step 6: Get certificates
$certificates = Get-IntuneCertificates

# Step 7: Get enrollment details
$enrollments = Get-EnrollmentDetails

# Step 8: Generate HTML Report
Generate-HTMLReport -DeviceInfo $deviceInfo `
                    -LocalPolicies $localPolicies `
                    -GraphPolicies $graphPolicies `
                    -AssignedPolicies $assignedPolicies `
                    -Applications $resolvedApps `
                    -Certificates $certificates `
                    -Enrollments $enrollments `
                    -OutputFile $reportFile

# Export detailed data to CSV
$csvPath = $reportFile -replace '\.html$', '_LocalPolicies.csv'
$localPolicies | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Local policies exported to CSV: $csvPath" -ForegroundColor Green

$csvPolicyPath = $reportFile -replace '\.html$', '_GraphPolicies.csv'
$graphPolicies | Export-Csv -Path $csvPolicyPath -NoTypeInformation
Write-Host "Graph policies exported to CSV: $csvPolicyPath" -ForegroundColor Green

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "   Report Generation Complete!   " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "`nHTML Report: $reportFile" -ForegroundColor White
Write-Host "CSV Exports: " -ForegroundColor White
Write-Host "  - $csvPath" -ForegroundColor Gray
Write-Host "  - $csvPolicyPath`n" -ForegroundColor Gray

# Disconnect from Graph
Disconnect-MgGraph | Out-Null
Write-Host "Disconnected from Microsoft Graph" -ForegroundColor Cyan

if ($OpenReport) {
    Start-Process $reportFile
}
#endregion
