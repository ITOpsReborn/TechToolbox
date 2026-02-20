<#
.SYNOPSIS
    Clean Declared Configuration and trigger Intune sync to rebuild policies
.DESCRIPTION
    Removes DMOrchestrator, DeclaredConfiguration, and related registry keys
    and files, then triggers MDM sync to re-download fresh policies from Intune
.NOTES
    Run as Administrator
    Tested on Windows 11 25H2
    Written By: Tim Knapp (Microsoft)
#>

Write-Host "=== Intune Declared Configuration Cleanup Script ===" -ForegroundColor Green
Write-Host "Starting cleanup process..." -ForegroundColor Yellow

# Find enrollment GUID
$EnrollmentGUID = (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" | 
    Get-ItemProperty | 
    Where-Object {$_.ProviderID -eq "MS DM Server"}).PSChildName

if (-not $EnrollmentGUID) {
    Write-Host "No Intune enrollment found!" -ForegroundColor Red
    exit 1
}

Write-Host "Enrollment GUID: $EnrollmentGUID" -ForegroundColor Cyan

# Find linked enrollment GUID
$LinkedEnrollmentID = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Enrollments\$EnrollmentGUID\LinkedEnrollment).LinkedEnrollmentID

If(-not $LinkedEnrollmentID) {
    Write-Host "No linked enrollment found" -ForegroundColor Red
} else {
    Write-Host "Linked Enrollment GUID: $LinkedEnrollmentID" -ForegroundColor Cyan
}

# 1. Remove DMOrchestrator (main EPM policy orchestrator)
$DMOrchestratorPath = "HKLM:\SOFTWARE\Microsoft\DMOrchestrator"
if (Test-Path $DMOrchestratorPath) {
    Remove-Item $DMOrchestratorPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Removed DMOrchestrator" -ForegroundColor Green
} else {
    Write-Host "DMOrchestrator not found" -ForegroundColor Gray
}

# 2. Remove DeclaredConfiguration
$DeclaredConfigPath = "HKLM:\SOFTWARE\Microsoft\DeclaredConfiguration"
if (Test-Path $DeclaredConfigPath) {
    Remove-Item $DeclaredConfigPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Removed DeclaredConfiguration" -ForegroundColor Green
} else {
    Write-Host "DeclaredConfiguration not found" -ForegroundColor Gray
}

# 3.a Remove EPMAgentClientSettings
$EPMClientSettings = "HKLM:\SOFTWARE\Microsoft\EPMAgent\Policies\ClientSettings"
if (Test-Path $EPMClientSettings) {
    Remove-Item $EPMClientSettings -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Removed EPMClientSettings" -ForegroundColor Green
} else {
    Write-Host "EPMClientSettings not found" -ForegroundColor Gray
}

# 3.b Remove EPMRegElevationRules
$EPMRegElevationRules = "HKLM:\SOFTWARE\Microsoft\EPMAgent\Policies\ElevationRules"
if (Test-Path $EPMRegElevationRules) {
    Remove-Item $EPMRegElevationRules -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Removed EPM Elevation Rules from registry" -ForegroundColor Green
} else {
    Write-Host "EPM Registry Elevation Rules not found" -ForegroundColor Gray
}

# 4.a Remove EPM Client Settings
$EPMSettingsFiles = "C:\Program Files\Microsoft EPM Agent\Policies\ClientSettings"
if (Test-Path $EPMSettingsFiles) {
    Remove-Item "$EPMSettingsFiles\*" -Force -ErrorAction SilentlyContinue
    Write-Host "Removed EPM Settings Files from: $EPMSettingsFiles" -ForegroundColor Green
} else {
    Write-Host "EPM Settings Files not found" -ForegroundColor Gray
}

# 4.b Remove EPM Elevation Rules
$EPMElevationRules = "C:\Program Files\Microsoft EPM Agent\Policies\ElevationRules"
if (Test-Path $EPMElevationRules) {
    Remove-Item "$EPMElevationRules\*" -Force -ErrorAction SilentlyContinue
    Write-Host "Removed EPM Elevation Rules from: $EPMElevationRules" -ForegroundColor Green
} else {
    Write-Host "EPM Elevation Rules not found" -ForegroundColor Gray
}

# 5. Remove Declared Configuration Files
$DCFiles = "C:\ProgramData\Microsoft\DC\HostOS"
if (Test-Path $DCFiles) {
    Remove-Item "$DCFiles\*" -Force -ErrorAction SilentlyContinue
    Write-Host "Removed Declared Configuration files from: $DCFiles" -ForegroundColor Green
} else {
    Write-Host "Declared Configuration files not found" -ForegroundColor Gray
}

# 6. Stop EPM Agent Service (if running)
$EPMSvc = Get-Service "Microsoft EPM Agent Service" -ErrorAction SilentlyContinue
if ($EPMSvc -and $EPMSvc.Status -eq 'Running') {
    Stop-Service "Microsoft EPM Agent Service" -Force
    Write-Host "Stopped EPM Agent Service" -ForegroundColor Green
}

# 7. Trigger Intune Sync
Write-Host "`nTriggering Intune sync to rebuild policies..." -ForegroundColor Yellow

# Method 1: PushLaunch task
$PushLaunchTask = Get-ScheduledTask -TaskName 'PushLaunch' -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$EnrollmentGUID\" -ErrorAction SilentlyContinue
if ($PushLaunchTask) {
    Start-ScheduledTask -TaskPath $PushLaunchTask.TaskPath -TaskName $PushLaunchTask.TaskName
    Write-Host "Triggered PushLaunch task" -ForegroundColor Green
    Write-Host "Will sleep for two minutes to complete" -ForegroundColor Yellow
    Start-Sleep -Seconds 120
} else {
    Write-Host "PushLaunch task not found" -ForegroundColor Yellow
}

# Method 2: Policy Refresh Agent
$PolicyRefreshTask = Get-ScheduledTask -TaskName 'Policy Manager Login Refresh Schedule' -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$EnrollmentGUID\" -ErrorAction SilentlyContinue
if ($PolicyRefreshTask) {
    Start-ScheduledTask -TaskPath $PolicyRefreshTask.TaskPath -TaskName $PolicyRefreshTask.TaskName
    Write-Host "Triggered PolicyRefresh task" -ForegroundColor Green
    Write-Host "Will sleep for two minutes to complete" -ForegroundColor Yellow
    Start-Sleep -Seconds 120
} else {
    Write-Host "PolicyRefresh task not found" -ForegroundColor Yellow
}

# Method 3: Intune 8 hour sync
$ScheduleThree = Get-ScheduledTask -TaskName 'Schedule #3 created by enrollment client' -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$EnrollmentGUID\" -ErrorAction SilentlyContinue
if ($ScheduleThree) {
    Start-ScheduledTask -TaskPath $ScheduleThree.TaskPath -TaskName $ScheduleThree.TaskName
    Write-Host "Triggered Schedule 3 task" -ForegroundColor Green
    Write-Host "Will sleep for two minutes to complete" -ForegroundColor Yellow
    Start-Sleep -Seconds 120
} else {
    Write-Host "Schedule 3 task not found" -ForegroundColor Yellow
}

# 8. Start Linked Enrollment Syncs

if ($LinkedEnrollmentID) {
    # Methord 1: Linked Schedule 3
    $LinkedScheduleThree = Get-ScheduledTask -TaskName 'Schedule #3 created by enrollment client' -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$LinkedEnrollmentID\" -ErrorAction SilentlyContinue
    if ($LinkedScheduleThree) {
        Start-ScheduledTask -TaskPath $LinkedScheduleThree.TaskPath -TaskName $LinkedScheduleThree.TaskName
        Write-Host "Triggered Linked Schedule 3 task" -ForegroundColor Green
        Write-Host "Will sleep for two minutes to complete" -ForegroundColor Yellow
        Start-Sleep -Seconds 120
    } else {
        Write-Host "Schedule 3 task not found" -ForegroundColor Yellow
    }

    # Methord 2: Declared Configuration Refresh
    $DCTaskRefresh = Get-ScheduledTask -TaskName 'Refresh schedule created by Declared Configuration to refresh any settings changed on the device' -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$LinkedEnrollmentID\" -ErrorAction SilentlyContinue
    if ($DCTaskRefresh) {
        Start-ScheduledTask -TaskPath $DCTaskRefresh.TaskPath -TaskName $DCTaskRefresh.TaskName
        Write-Host "Triggered Declared Configuration Refresh" -ForegroundColor Green
        Write-Host "Will sleep for two minutes to complete" -ForegroundColor Yellow
        Start-Sleep -Seconds 120
    } else {
        Write-Host "Declared Configuration task not found" -ForegroundColor Yellow
    }
} else {
    Write-Host "No Linked Enrollment ID Found... Skipping..." -ForegroundColor Yellow
}


# 9. Restart EPM Agent Service
if ($EPMSvc) {
    Start-Sleep -Seconds 5
    Start-Service "Microsoft EPM Agent Service"
    Write-Host "Started EPM Agent Service" -ForegroundColor Green
}

Write-Host "`n=== Cleanup complete! ===" -ForegroundColor Green
Write-Host "Policies will be re-downloaded automatically within minutes." -ForegroundColor Cyan
Write-Host "Monitor Event Viewer > Applications and Services Logs > Microsoft > Windows > DeviceManagement-Enterprise-Diagnostics-Provider for sync status." -ForegroundColor Cyan
