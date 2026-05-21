# Windows Autopatch / Windows Update Repair Script
# Intended for Intune Proactive Remediation or IME execution
# Requires elevation
# Reboot required

$LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile = Join-Path $LogPath "Autopatch-Repair.log"

function Write-Log {
    param (
        [string]$Message
    )
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "$TimeStamp`t$Message"
    Add-Content -Path $LogFile -Value $Entry
}

Write-Log "===== Autopatch Repair Started ====="

# Define services
$UpdateServices = @(
    "wuauserv",
    "bits",
    "cryptsvc",
    "msiserver"
)

# Stop services
Write-Log "Stopping Windows Update services"
foreach ($Service in $UpdateServices) {
    $svc = Get-Service -Name $Service -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne "Stopped") {
        Write-Log "Stopping service: $Service"
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
    }
}

# DISM RestoreHealth
Write-Log "Starting DISM RestoreHealth"
$DismResult = Start-Process -FilePath "DISM.exe" `
    -ArgumentList "/Online /Cleanup-Image /RestoreHealth /NoRestart" `
    -Wait -PassThru
Write-Log "DISM completed with exit code $($DismResult.ExitCode)"

# Reset SoftwareDistribution and Catroot2
$SDPath = "C:\Windows\SoftwareDistribution"
$CRPath = "C:\Windows\System32\catroot2"

if (Test-Path $SDPath) {
    Write-Log "Renaming SoftwareDistribution"
    Rename-Item -Path $SDPath -NewName "SoftwareDistribution.old" -Force -ErrorAction SilentlyContinue
}

if (Test-Path $CRPath) {
    Write-Log "Renaming catroot2"
    Rename-Item -Path $CRPath -NewName "catroot2.old" -Force -ErrorAction SilentlyContinue
}

# Re-register Windows Update DLLs
Write-Log "Re-registering Windows Update components"

$WUDlls = @(
    "atl.dll",
    "urlmon.dll",
    "mshtml.dll",
    "wuapi.dll",
    "wuaueng.dll",
    "wucltux.dll",
    "wups.dll",
    "wups2.dll",
    "wuwebv.dll",
    "qmgr.dll",
    "qmgrprxy.dll"
)

foreach ($Dll in $WUDlls) {
    Write-Log "Registering $Dll"
    Start-Process "regsvr32.exe" -ArgumentList "/s $Dll" -Wait
}

# Start services
Write-Log "Starting Windows Update services"
foreach ($Service in $UpdateServices) {
    Write-Log "Starting service: $Service"
    Start-Service -Name $Service -ErrorAction SilentlyContinue
}

# Trigger update scan
Write-Log "Triggering Windows Update scan"
Start-Process "usoclient.exe" -ArgumentList "StartScan" -NoNewWindow

Write-Log "Autopatch repair completed. Reboot required."
Write-Log "===== Autopatch Repair Finished ====="