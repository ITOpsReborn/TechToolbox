<#
.SYNOPSIS
    Enhanced Local Intune RSOP - Decodes Policy Values with Friendly Names
.DESCRIPTION
    Generates an HTML report showing all Intune policies with decoded configuration values
    and human-readable names. Reads from local registry and translates CSP URIs to friendly names.
.PARAMETER OutputPath
    Path where HTML report will be saved. Defaults to user's Desktop.
.PARAMETER OpenReport
    Automatically open the HTML report after generation.
.EXAMPLE
    .\Get-LocalIntuneRSOP-Enhanced.ps1 -OpenReport
.NOTES
    Requires: Local Administrator rights for full registry access
    No external modules needed - uses native Windows tools
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
    exit
}
#endregion

#region Helper Functions
function Get-FriendlyPolicyName {
    param([string]$PolicyArea, [string]$PolicyName)
    
    # Map common CSP areas to friendly names
    $areaMapping = @{
        'BitLocker' = 'BitLocker Encryption'
        'DeviceLock' = 'Device Lock & Screen'
        'Defender' = 'Microsoft Defender'
        'Update' = 'Windows Update'
        'WindowsDefenderSecurityCenter' = 'Windows Security Center'
        'ControlPolicyConflict' = 'Policy Conflict Resolution'
        'DeliveryOptimization' = 'Delivery Optimization'
        'Experience' = 'Windows Experience'
        'Privacy' = 'Privacy Settings'
        'System' = 'System Configuration'
        'WiFi' = 'Wi-Fi Settings'
        'Bluetooth' = 'Bluetooth Settings'
        'Browser' = 'Browser Settings'
        'Connectivity' = 'Network Connectivity'
        'DesktopAppInstaller' = 'App Installer'
        'Camera' = 'Camera Settings'
        'Storage' = 'Storage Management'
        'Security' = 'Security Policies'
        'LocalPoliciesSecurityOptions' = 'Local Security Options'
        'UserRights' = 'User Rights Assignment'
        'ApplicationManagement' = 'Application Management'
        'Cellular' = 'Cellular Settings'
        'RemoteDesktop' = 'Remote Desktop'
        'Search' = 'Windows Search'
        'TextInput' = 'Text Input & Typing'
        'WindowsLogon' = 'Windows Logon'
        'WirelessDisplay' = 'Wireless Display'
        'SmartScreen' = 'SmartScreen Filter'
        'AppRuntime' = 'App Runtime Settings'
        'LockDown' = 'Kiosk & LockDown'
        'MixedReality' = 'Mixed Reality'
        'Notifications' = 'Notification Settings'
        'Start' = 'Start Menu & Taskbar'
        'TimeLanguageSettings' = 'Time & Language'
    }
    
    # Map specific policy names to friendly descriptions
    $policyMapping = @{
        'AllowAutoUpdate' = 'Allow Automatic Updates'
        'AllowCortana' = 'Allow Cortana'
        'AllowLocation' = 'Allow Location Services'
        'AllowTelemetry' = 'Diagnostic Data Level'
        'RequireDeviceEncryption' = 'Require Device Encryption'
        'AllowManualMDMUnenrollment' = 'Allow Manual MDM Unenrollment'
        'PreventAutomaticDeviceEncryptionForAzureADJoinedDevices' = 'Prevent Automatic Encryption (Azure AD)'
        'AllowWindowsSpotlight' = 'Allow Windows Spotlight'
        'DevicePasswordEnabled' = 'Require Password'
        'MinDevicePasswordLength' = 'Minimum Password Length'
        'DevicePasswordHistory' = 'Password History'
        'MaxDevicePasswordFailedAttempts' = 'Max Failed Password Attempts'
        'MaxInactivityTimeDeviceLock' = 'Max Inactivity Before Lock (minutes)'
        'MinDevicePasswordComplexCharacters' = 'Password Complexity'
        'AlphanumericDevicePasswordRequired' = 'Alphanumeric Password Required'
        'AllowSimpleDevicePassword' = 'Allow Simple Password'
        'DevicePasswordExpiration' = 'Password Expiration (days)'
        'AllowAddProvisioningPackage' = 'Allow Provisioning Packages'
        'AllowBluetooth' = 'Allow Bluetooth'
        'AllowCamera' = 'Allow Camera'
        'AllowDateTimeSettings' = 'Allow Date/Time Changes'
        'AllowVPN' = 'Allow VPN'
        'EnableSmartScreen' = 'Enable SmartScreen'
        'PUAProtection' = 'Potentially Unwanted App Protection'
        'CloudBlockLevel' = 'Cloud Block Level'
        'CloudExtendedTimeout' = 'Cloud Extended Timeout'
        'RealTimeScanDirection' = 'Real-Time Scan Direction'
        'AllowBehaviorMonitoring' = 'Behavior Monitoring'
        'AllowCloudProtection' = 'Cloud Protection'
        'AllowIOAVProtection' = 'IOAV Protection'
        'AllowIntrusionPreventionSystem' = 'Network Protection'
        'AllowOnAccessProtection' = 'On Access Protection'
        'AllowRealtimeMonitoring' = 'Real-Time Monitoring'
        'AllowScanningNetworkFiles' = 'Scan Network Files'
        'AllowScriptScanning' = 'Script Scanning'
        'SubmitSamplesConsent' = 'Sample Submission'
    }
    
    $friendlyArea = if ($areaMapping.ContainsKey($PolicyArea)) { $areaMapping[$PolicyArea] } else { $PolicyArea -replace "([a-z])([A-Z])", '$1 $2' }
    $friendlyPolicy = if ($policyMapping.ContainsKey($PolicyName)) { $policyMapping[$PolicyName] } else { $PolicyName -replace "([a-z])([A-Z])", '$1 $2' }
    
    return [PSCustomObject]@{
        FriendlyArea = $friendlyArea
        FriendlyPolicy = $friendlyPolicy
    }
}

function Decode-PolicyValue {
    param(
        [string]$PolicyArea,
        [string]$PolicyName,
        $Value
    )
    
    # Common value mappings
    if ($Value -eq 0 -or $Value -eq '0' -or $Value -eq $false) {
        # Check context-specific meanings
        switch -Regex ("$PolicyArea\$PolicyName") {
            ".*Allow.*" { return "Blocked / Disabled" }
            ".*Enable.*" { return "Disabled" }
            ".*Require.*" { return "Not Required" }
            default { return "Disabled / No / False" }
        }
    }
    
    if ($Value -eq 1 -or $Value -eq '1' -or $Value -eq $true) {
        switch -Regex ("$PolicyArea\$PolicyName") {
            ".*Allow.*" { return "Allowed / Enabled" }
            ".*Enable.*" { return "Enabled" }
            ".*Require.*" { return "Required" }
            default { return "Enabled / Yes / True" }
        }
    }
    
    # Specific policy value mappings
    $valueMap = @{
        # Telemetry levels
        'AllowTelemetry' = @{
            '0' = 'Security (Enterprise Only)'
            '1' = 'Basic'
            '2' = 'Enhanced'
            '3' = 'Full'
        }
        # Password complexity
        'MinDevicePasswordComplexCharacters' = @{
            '1' = 'Digits only'
            '2' = 'Digits and lowercase'
            '3' = 'Digits, lowercase, and uppercase'
            '4' = 'Digits, lowercase, uppercase, and special'
        }
        # BitLocker encryption methods
        'EncryptionMethod' = @{
            '3' = 'AES-CBC 128'
            '4' = 'AES-CBC 256'
            '6' = 'XTS-AES 128'
            '7' = 'XTS-AES 256'
        }
        # Defender PUA Protection
        'PUAProtection' = @{
            '0' = 'Disabled'
            '1' = 'Enabled (Block)'
            '2' = 'Audit Mode'
        }
        # Cloud Block Level
        'CloudBlockLevel' = @{
            '0' = 'Default'
            '2' = 'High'
            '4' = 'High Plus'
            '6' = 'Zero Tolerance'
        }
        # Sample Submission
        'SubmitSamplesConsent' = @{
            '0' = 'Always Prompt'
            '1' = 'Send Safe Samples'
            '2' = 'Never Send'
            '3' = 'Send All Samples'
        }
        # Scan Direction
        'RealTimeScanDirection' = @{
            '0' = 'Monitor All (default)'
            '1' = 'Monitor Incoming'
            '2' = 'Monitor Outgoing'
        }
    }
    
    # Check if we have a specific mapping for this policy
    foreach ($key in $valueMap.Keys) {
        if ($PolicyName -like "*$key*" -and $valueMap[$key].ContainsKey($Value.ToString())) {
            return $valueMap[$key][$Value.ToString()]
        }
    }
    
    # Handle XML data (BitLocker, complex policies)
    if ($Value -match '<enabled/>') {
        $xmlData = @()
        if ($Value -match 'data id="([^"]+)"\s+value="([^"]+)"') {
            $matches = [regex]::Matches($Value, 'data id="([^"]+)"\s+value="([^"]+)"')
            foreach ($match in $matches) {
                $settingName = $match.Groups[1].Value -replace 'EncryptionMethodWithXts', 'Encryption: ' -replace 'DropDown_Name', '' -replace 'Os', 'OS Drive' -replace 'Fdv', 'Fixed Drive' -replace 'Rdv', 'Removable Drive'
                $settingValue = switch ($match.Groups[2].Value) {
                    '3' { 'AES-CBC 128' }
                    '4' { 'AES-CBC 256' }
                    '6' { 'XTS-AES 128' }
                    '7' { 'XTS-AES 256' }
                    'true' { 'Enabled' }
                    'false' { 'Disabled' }
                    default { $match.Groups[2].Value }
                }
                $xmlData += "$settingName = $settingValue"
            }
        }
        if ($xmlData.Count -gt 0) {
            return "Enabled: " + ($xmlData -join '; ')
        }
        return "Enabled"
    }
    
    # Time values (often in minutes or seconds)
    if ($PolicyName -match 'Timeout|Inactivity|Interval|Period|Expiration|MaxInactivityTime') {
        if ([int]::TryParse($Value, [ref]$null)) {
            $numValue = [int]$Value
            if ($PolicyName -match 'Password') {
                return "$numValue days"
            } elseif ($numValue -ge 60) {
                return "$([math]::Round($numValue / 60, 1)) hours ($numValue minutes)"
            } else {
                return "$numValue minutes"
            }
        }
    }
    
    # Size values
    if ($PolicyName -match 'Size|Length' -and [int]::TryParse($Value, [ref]$null)) {
        return "$Value characters"
    }
    
    # URLs
    if ($Value -match '^https?://') {
        return $Value
    }
    
    # If value is too long, truncate it
    if ($Value.ToString().Length -gt 100) {
        return $Value.ToString().Substring(0, 97) + "..."
    }
    
    return $Value
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
    
    # Get Intune Enrollment ID (Provider GUID)
    try {
        $dmClientPath = "C:\ProgramData\Microsoft\DMClient"
        if (Test-Path $dmClientPath) {
            $enrollmentFolder = Get-ChildItem -Path $dmClientPath -Directory | Select-Object -First 1
            if ($enrollmentFolder) {
                $deviceInfo | Add-Member -NotePropertyName "IntuneEnrollmentID" -NotePropertyValue $enrollmentFolder.Name
            }
        }
    } catch {
        $deviceInfo | Add-Member -NotePropertyName "IntuneEnrollmentID" -NotePropertyValue "Not Available"
    }
    
    # Get Azure AD Device ID
    try {
        $dsregStatus = & dsregcmd /status
        $aadDeviceId = ($dsregStatus | Select-String "DeviceId" | Select-Object -First 1) -replace '.*:\s*', ''
        $deviceInfo | Add-Member -NotePropertyName "AzureADDeviceID" -NotePropertyValue $aadDeviceId.Trim()
        
        $tenantId = ($dsregStatus | Select-String "TenantId" | Select-Object -First 1) -replace '.*:\s*', ''
        $deviceInfo | Add-Member -NotePropertyName "TenantID" -NotePropertyValue $tenantId.Trim()
    } catch {
        $deviceInfo | Add-Member -NotePropertyName "AzureADDeviceID" -NotePropertyValue "Not Available"
        $deviceInfo | Add-Member -NotePropertyName "TenantID" -NotePropertyValue "Not Available"
    }
    
    # Check Enrollment Status
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

function Get-IntuneProviderGUID {
    Write-Host "Identifying Intune Provider GUID..." -ForegroundColor Cyan
    
    # Method 1: Check DMClient folder
    $dmClientPath = "C:\ProgramData\Microsoft\DMClient"
    if (Test-Path $dmClientPath) {
        $enrollmentFolder = Get-ChildItem -Path $dmClientPath -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($enrollmentFolder) {
            Write-Host "Found Provider GUID: $($enrollmentFolder.Name)" -ForegroundColor Green
            return $enrollmentFolder.Name
        }
    }
    
    # Method 2: Check Enrollments registry
    $enrollmentsPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
    if (Test-Path $enrollmentsPath) {
        $enrollments = Get-ChildItem -Path $enrollmentsPath -ErrorAction SilentlyContinue
        foreach ($enrollment in $enrollments) {
            $props = Get-ItemProperty -Path $enrollment.PSPath -ErrorAction SilentlyContinue
            if ($props.ProviderID -match "MS DM Server") {
                Write-Host "Found Provider GUID: $($enrollment.PSChildName)" -ForegroundColor Green
                return $enrollment.PSChildName
            }
        }
    }
    
    Write-Warning "Could not identify Intune Provider GUID"
    return $null
}

function Get-MDMPoliciesWithValues {
    param([string]$ProviderGUID)
    
    Write-Host "Collecting MDM policies with decoded values..." -ForegroundColor Cyan
    
    $policies = @()
    
    # Path 1: Current Device Policies (What's actually applied)
    $currentPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device"
    
    if (Test-Path $currentPath) {
        $policyAreas = Get-ChildItem -Path $currentPath -ErrorAction SilentlyContinue
        
        foreach ($area in $policyAreas) {
            $areaName = $area.PSChildName
            
            try {
                $properties = Get-ItemProperty -Path $area.PSPath -ErrorAction SilentlyContinue
                
                foreach ($prop in $properties.PSObject.Properties) {
                    if ($prop.Name -notmatch "^PS" -and $prop.Value) {
                        $friendly = Get-FriendlyPolicyName -PolicyArea $areaName -PolicyName $prop.Name
                        $decodedValue = Decode-PolicyValue -PolicyArea $areaName -PolicyName $prop.Name -Value $prop.Value
                        
                        $policies += [PSCustomObject]@{
                            Category = $friendly.FriendlyArea
                            Setting = $friendly.FriendlyPolicy
                            RawName = "$areaName\$($prop.Name)"
                            Value = $decodedValue
                            RawValue = $prop.Value
                            Source = "Applied (Current)"
                            Status = "Active"
                        }
                    }
                }
            } catch {
                Write-Verbose "Could not read area: $areaName"
            }
        }
    }
    
    # Path 2: Provider-specific policies (What Intune sent)
    if ($ProviderGUID) {
        $providerPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$ProviderGUID\default\Device"
        
        if (Test-Path $providerPath) {
            $providerAreas = Get-ChildItem -Path $providerPath -ErrorAction SilentlyContinue
            
            foreach ($area in $providerAreas) {
                $areaName = $area.PSChildName
                
                try {
                    $properties = Get-ItemProperty -Path $area.PSPath -ErrorAction SilentlyContinue
                    
                    foreach ($prop in $properties.PSObject.Properties) {
                        if ($prop.Name -notmatch "^PS" -and $prop.Value -and $prop.Name -notmatch "_WinningProvider|_Provider|_Providers") {
                            # Check if this policy is already in the applied list
                            $exists = $policies | Where-Object { $_.RawName -eq "$areaName\$($prop.Name)" }
                            
                            if (-not $exists) {
                                $friendly = Get-FriendlyPolicyName -PolicyArea $areaName -PolicyName $prop.Name
                                $decodedValue = Decode-PolicyValue -PolicyArea $areaName -PolicyName $prop.Name -Value $prop.Value
                                
                                $policies += [PSCustomObject]@{
                                    Category = $friendly.FriendlyArea
                                    Setting = $friendly.FriendlyPolicy
                                    RawName = "$areaName\$($prop.Name)"
                                    Value = $decodedValue
                                    RawValue = $prop.Value
                                    Source = "Intune (Pending/Not Applied)"
                                    Status = "Pending"
                                }
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Could not read provider area: $areaName"
                }
            }
        }
    }
    
    Write-Host "Found $($policies.Count) policies" -ForegroundColor Green
    return $policies | Sort-Object Category, Setting
}

function Get-EnrolledMDMDetails {
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
                    default { $props.EnrollmentType }
                }
                EnrollmentState = switch ($props.EnrollmentState) {
                    1 { "Enrolled" }
                    2 { "Failed" }
                    3 { "Pending" }
                    default { $props.EnrollmentState }
                }
                AADDeviceID = $props.AADDeviceID
                DMPServerURL = $props.DiscoveryServiceFullURL
            }
        }
    }
    
    return $enrollments
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
                    $_.Subject -match "Intune|Microsoft|MDM" -or
                    $_.Extensions.Oid.FriendlyName -match "MDM"
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

function Get-IntuneApplications {
    Write-Host "Collecting Intune-managed applications..." -ForegroundColor Cyan
    
    $apps = @()
    $win32AppPath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
    
    if (Test-Path $win32AppPath) {
        $userSIDs = Get-ChildItem -Path $win32AppPath -ErrorAction SilentlyContinue
        
        foreach ($sid in $userSIDs) {
            $appGUIDs = Get-ChildItem -Path $sid.PSPath -ErrorAction SilentlyContinue
            
            foreach ($appGUID in $appGUIDs) {
                $appProps = Get-ItemProperty -Path $appGUID.PSPath -ErrorAction SilentlyContinue
                
                $installState = switch ($appProps.InstallState) {
                    1 { "Installed" }
                    2 { "Not Installed" }
                    3 { "Installing" }
                    default { $appProps.InstallState }
                }
                
                $complianceState = switch ($appProps.ComplianceState) {
                    0 { "Unknown" }
                    1 { "Compliant" }
                    2 { "Not Compliant" }
                    3 { "In Grace Period" }
                    default { $appProps.ComplianceState }
                }
                
                $apps += [PSCustomObject]@{
                    AppGUID = $appGUID.PSChildName
                    UserSID = $sid.PSChildName
                    InstallState = $installState
                    ComplianceState = $complianceState
                    EnforcementState = $appProps.EnforcementState
                    LastUpdateTime = $appProps.LastUpdateTimeUtc
                }
            }
        }
    }
    
    return $apps
}

function Generate-HTMLReport {
    param(
        [object]$DeviceInfo,
        [array]$Policies,
        [array]$Enrollments,
        [array]$Certificates,
        [array]$Applications,
        [string]$OutputFile
    )
    
    Write-Host "Generating HTML report with decoded values..." -ForegroundColor Cyan
    
    # Group policies by category
    $policiesByCategory = $Policies | Group-Object -Property Category
    
    # Count statistics
    $appliedCount = ($Policies | Where-Object { $_.Status -eq "Active" }).Count
    $pendingCount = ($Policies | Where-Object { $_.Status -eq "Pending" }).Count
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Intune RSOP Report - $($DeviceInfo.DeviceName)</title>
    <style>
        * { box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0;
            padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 30px;
        }
        h1 { 
            color: #0078d4; 
            border-bottom: 4px solid #0078d4; 
            padding-bottom: 15px;
            margin-top: 0;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        h2 { 
            color: #106ebe; 
            margin-top: 40px; 
            border-left: 6px solid #0078d4;
            padding-left: 15px;
            background: linear-gradient(90deg, #f0f8ff 0%, transparent 100%);
            padding-top: 10px;
            padding-bottom: 10px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.15);
            transition: transform 0.3s;
        }
        .summary-card:hover {
            transform: translateY(-5px);
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            font-size: 14px;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .summary-card .value {
            font-size: 42px;
            font-weight: bold;
            margin: 0;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .info-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #0078d4;
        }
        .info-item strong {
            display: block;
            color: #106ebe;
            margin-bottom: 5px;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .info-item span {
            color: #333;
            font-size: 15px;
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin: 20px 0;
            background-color: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        th { 
            background: linear-gradient(135deg, #0078d4 0%, #106ebe 100%);
            color: white; 
            padding: 15px; 
            text-align: left;
            font-weight: 600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        td { 
            padding: 12px 15px; 
            border-bottom: 1px solid #e9ecef;
            vertical-align: top;
        }
        tr:hover { 
            background-color: #f8f9fa;
        }
        tr:last-child td {
            border-bottom: none;
        }
        .status-active { 
            color: #107c10; 
            font-weight: bold;
            background: #dff6dd;
            padding: 4px 12px;
            border-radius: 12px;
            display: inline-block;
            font-size: 12px;
        }
        .status-pending { 
            color: #ca5010; 
            font-weight: bold;
            background: #fff4ce;
            padding: 4px 12px;
            border-radius: 12px;
            display: inline-block;
            font-size: 12px;
        }
        .status-enrolled { 
            color: #107c10; 
            font-weight: bold;
        }
        .status-not-enrolled { 
            color: #d13438; 
            font-weight: bold;
        }
        .collapsible {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            cursor: pointer;
            padding: 18px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 16px;
            margin-top: 15px;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .collapsible:hover {
            transform: translateX(5px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
        }
        .collapsible:after {
            content: '\\002B';
            color: white;
            font-weight: bold;
            float: right;
            font-size: 20px;
        }
        .collapsible.active:after {
            content: "\\2212";
        }
        .content {
            padding: 0;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
            background-color: white;
        }
        .content.active {
            padding: 20px;
            max-height: 5000px;
        }
        .footer {
            margin-top: 50px;
            padding: 25px;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 8px;
            text-align: center;
            color: #666;
            border-top: 3px solid #0078d4;
        }
        .raw-value {
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
            color: #666;
        }
        .category-section {
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #dee2e6;
        }
        .category-header {
            color: #0078d4;
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #0078d4;
        }
        .policy-row {
            display: grid;
            grid-template-columns: 1fr 2fr auto;
            gap: 15px;
            padding: 12px;
            background: white;
            margin: 8px 0;
            border-radius: 6px;
            border-left: 4px solid #0078d4;
            align-items: center;
        }
        .policy-name {
            font-weight: 600;
            color: #333;
        }
        .policy-value {
            color: #0078d4;
            font-weight: 500;
        }
        .search-box {
            width: 100%;
            padding: 12px;
            margin: 20px 0;
            border: 2px solid #0078d4;
            border-radius: 8px;
            font-size: 16px;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M4 6H20M4 12H20M4 18H20" stroke="#0078d4" stroke-width="2" stroke-linecap="round"/>
        </svg>
        Intune RSOP Report
    </h1>
    <p style="color: #666; font-size: 14px;"><strong>Generated:</strong> $(Get-Date -Format "dddd, MMMM dd, yyyy 'at' hh:mm:ss tt")</p>
    
    <h2>📊 Policy Summary</h2>
    <div class="summary-grid">
        <div class="summary-card">
            <h3>Total Policies</h3>
            <p class="value">$($Policies.Count)</p>
        </div>
        <div class="summary-card">
            <h3>Applied</h3>
            <p class="value">$appliedCount</p>
        </div>
        <div class="summary-card">
            <h3>Pending</h3>
            <p class="value">$pendingCount</p>
        </div>
        <div class="summary-card">
            <h3>Categories</h3>
            <p class="value">$($policiesByCategory.Count)</p>
        </div>
    </div>
    
    <h2>💻 Device Information</h2>
    <div class="info-grid">
        <div class="info-item"><strong>Device Name</strong><span>$($DeviceInfo.DeviceName)</span></div>
        <div class="info-item"><strong>User</strong><span>$($DeviceInfo.UserName)</span></div>
        <div class="info-item"><strong>OS Version</strong><span>$($DeviceInfo.OSVersion)</span></div>
        <div class="info-item"><strong>OS Build</strong><span>$($DeviceInfo.OSBuild)</span></div>
        <div class="info-item"><strong>Architecture</strong><span>$($DeviceInfo.OSArchitecture)</span></div>
        <div class="info-item"><strong>Last Boot</strong><span>$($DeviceInfo.LastBootTime.ToString("yyyy-MM-dd HH:mm:ss"))</span></div>
        <div class="info-item"><strong>Domain</strong><span>$($DeviceInfo.Domain)</span></div>
        <div class="info-item"><strong>Manufacturer</strong><span>$($DeviceInfo.Manufacturer)</span></div>
        <div class="info-item"><strong>Model</strong><span>$($DeviceInfo.Model)</span></div>
        <div class="info-item"><strong>Serial Number</strong><span>$($DeviceInfo.SerialNumber)</span></div>
        <div class="info-item"><strong>Enrollment ID</strong><span>$($DeviceInfo.IntuneEnrollmentID)</span></div>
        <div class="info-item"><strong>Azure AD Device ID</strong><span>$($DeviceInfo.AzureADDeviceID)</span></div>
        <div class="info-item"><strong>Tenant ID</strong><span>$($DeviceInfo.TenantID)</span></div>
        <div class="info-item"><strong>MDM Status</strong><span class="$('status-' + $DeviceInfo.MDMEnrollmentStatus.ToLower() -replace ' ','-')">$($DeviceInfo.MDMEnrollmentStatus)</span></div>
    </div>
    
    <h2>⚙️ Applied Policies by Category</h2>
    <input type="text" id="policySearch" class="search-box" placeholder="🔍 Search policies by name, category, or value..." onkeyup="filterPolicies()">
    
    <div id="policiesContainer">
"@
    
    foreach ($category in ($policiesByCategory | Sort-Object Name)) {
        $categoryPolicies = $category.Group | Sort-Object Setting
        
        $htmlReport += @"
    <div class="category-section policy-category">
        <div class="category-header">$($category.Name) ($($categoryPolicies.Count) settings)</div>
"@
        
        foreach ($policy in $categoryPolicies) {
            $statusClass = if ($policy.Status -eq "Active") { "status-active" } else { "status-pending" }
            
            $htmlReport += @"
        <div class="policy-row">
            <div class="policy-name">$($policy.Setting)</div>
            <div class="policy-value">$($policy.Value)</div>
            <span class="$statusClass">$($policy.Status)</span>
        </div>
"@
        }
        
        $htmlReport += @"
    </div>
"@
    }
    
    $htmlReport += @"
    </div>
    
    <button type="button" class="collapsible">📋 Enrollment Details ($($Enrollments.Count))</button>
    <div class="content">
        <table>
            <tr>
                <th>Enrollment GUID</th>
                <th>Provider ID</th>
                <th>UPN</th>
                <th>Type</th>
                <th>State</th>
            </tr>
"@
    
    foreach ($enrollment in $Enrollments) {
        $htmlReport += @"
            <tr>
                <td><span class="raw-value">$($enrollment.EnrollmentGUID)</span></td>
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
    
    <button type="button" class="collapsible">🔐 Certificates ($($Certificates.Count))</button>
    <div class="content">
        <table>
            <tr>
                <th>Store</th>
                <th>Subject</th>
                <th>Issuer</th>
                <th>Valid Until</th>
                <th>Days Remaining</th>
            </tr>
"@
    
    foreach ($cert in $Certificates) {
        $daysColor = if ($cert.DaysUntilExpiry -lt 30) { "color: #d13438;" } elseif ($cert.DaysUntilExpiry -lt 90) { "color: #ca5010;" } else { "color: #107c10;" }
        
        $htmlReport += @"
            <tr>
                <td>$($cert.Store)</td>
                <td>$($cert.Subject)</td>
                <td>$($cert.Issuer)</td>
                <td>$($cert.NotAfter.ToString("yyyy-MM-dd"))</td>
                <td style="$daysColor font-weight: bold;">$($cert.DaysUntilExpiry) days</td>
            </tr>
"@
    }
    
    $htmlReport += @"
        </table>
    </div>
    
    <button type="button" class="collapsible">📱 Win32 Applications ($($Applications.Count))</button>
    <div class="content">
        <table>
            <tr>
                <th>App GUID</th>
                <th>Install State</th>
                <th>Compliance State</th>
                <th>Last Update</th>
            </tr>
"@
    
    foreach ($app in $Applications) {
        $htmlReport += @"
            <tr>
                <td><span class="raw-value">$($app.AppGUID)</span></td>
                <td>$($app.InstallState)</td>
                <td>$($app.ComplianceState)</td>
                <td>$($app.LastUpdateTime)</td>
            </tr>
"@
    }
    
    $htmlReport += @"
        </table>
    </div>
    
    <div class="footer">
        <h3 style="margin-top: 0; color: #0078d4;">Intune RSOP Report</h3>
        <p style="margin: 10px 0;">Generated on <strong>$($DeviceInfo.DeviceName)</strong></p>
        <p style="margin: 10px 0;">PowerShell Version: <strong>$($PSVersionTable.PSVersion)</strong></p>
        <p style="margin: 10px 0; font-size: 13px;">This report displays the Resultant Set of Policies (RSOP) applied to this device through Microsoft Intune MDM</p>
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
    
    // Search/Filter functionality
    function filterPolicies() {
        var input = document.getElementById("policySearch");
        var filter = input.value.toUpperCase();
        var categories = document.getElementsByClassName("policy-category");
        
        for (var i = 0; i < categories.length; i++) {
            var category = categories[i];
            var categoryHeader = category.getElementsByClassName("category-header")[0];
            var policyRows = category.getElementsByClassName("policy-row");
            var visibleCount = 0;
            
            for (var j = 0; j < policyRows.length; j++) {
                var row = policyRows[j];
                var txtValue = row.textContent || row.innerText;
                
                if (txtValue.toUpperCase().indexOf(filter) > -1) {
                    row.style.display = "";
                    visibleCount++;
                } else {
                    row.style.display = "none";
                }
            }
            
            // Hide category if no visible policies
            if (visibleCount > 0 || filter === "") {
                category.style.display = "";
            } else {
                category.style.display = "none";
            }
        }
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
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   Intune RSOP - Enhanced with Value Decoding   " -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = Join-Path $OutputPath "IntuneRSOP_$env:COMPUTERNAME`_$timestamp.html"

# Collect all data
$deviceInfo = Get-IntuneDeviceInfo
$providerGUID = Get-IntuneProviderGUID
$policies = Get-MDMPoliciesWithValues -ProviderGUID $providerGUID
$enrollments = Get-EnrolledMDMDetails
$certificates = Get-IntuneCertificates
$applications = Get-IntuneApplications

# Generate HTML Report
Generate-HTMLReport -DeviceInfo $deviceInfo `
                    -Policies $policies `
                    -Enrollments $enrollments `
                    -Certificates $certificates `
                    -Applications $applications `
                    -OutputFile $reportFile

# Export policies to CSV for detailed analysis
$csvPath = $reportFile -replace '\.html$', '_DetailedPolicies.csv'
$policies | Select-Object Category, Setting, Value, RawValue, Status, Source | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Policy details exported to CSV: $csvPath" -ForegroundColor Green

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host "   Report Generation Complete!   " -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host "`nReport location: $reportFile" -ForegroundColor White
Write-Host "CSV export: $csvPath`n" -ForegroundColor White

if ($OpenReport) {
    Start-Process $reportFile
}
#endregion
