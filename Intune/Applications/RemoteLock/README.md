# Remote Lockout - Intune Win32 Application

## Overview

Remote Lockout is a PowerShell-based Win32 application deployed via Microsoft Intune that takes over the Windows login screen with a custom image and message, logs out all active user sessions, and disables interactive logon to prevent anyone from signing back in.

This is designed for scenarios such as lost/stolen devices, terminated employees, or security incidents where immediate device lockdown is required.

## What It Does

### Install (Lockout)

1. Reads configuration from the XML file (image, text, color)
2. Stages all files to `C:\Windows\IntuneApps\RemoteLockout`
3. Backs up current login screen and security settings
4. Replaces the lock screen image with the specified image
5. Sets legal notice text (displayed before any logon attempt)
6. Hides the user list on the logon screen
7. Disables all local user accounts
8. Denies interactive logon rights for Users and Administrators groups
9. Enforces Ctrl+Alt+Del requirement
10. Logs off all active user sessions

### Uninstall (Restore)

1. Restores the original lock screen and legal notice settings
2. Re-enables all previously active user accounts
3. Restores the original security policy (interactive logon rights)
4. Removes the staging directory and all lockout files
5. Re-enables Windows Spotlight

## Files

| File | Purpose |
|------|---------|
| `Invoke-RemoteLockout.ps1` | Main script (install and uninstall) |
| `RemoteLockout.xml` | Configuration file (image, text, color) |
| `LockScreen.png` | Lock screen background image (1920x1080, black) |
| `RemoteLockout-Logo.svg` | App logo source (vector) |
| `RemoteLockout-Logo.png` | App logo for Intune (512x512) |

## Configuration (XML)

Edit `RemoteLockout.xml` to customize the lockout experience:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<RemoteLockout>
    <LockImage>LockScreen.png</LockImage>
    <Line1>This device has been remotely locked.</Line1>
    <Line2>Contact your IT administrator for assistance.</Line2>
    <TextColor>#FFFFFF</TextColor>
</RemoteLockout>
```

| Element | Description |
|---------|-------------|
| `LockImage` | Filename of the lock screen image (relative to script directory) or an absolute path |
| `Line1` | First line of text displayed on the login screen (Legal Notice Caption) |
| `Line2` | Second line of text displayed on the login screen (Legal Notice Text) |
| `TextColor` | Hex color for the text (e.g., `#FFFFFF` for white, `#FF0000` for red) |

### Multiple Scenarios

You can create multiple XML files for different lockout scenarios:

- `LostDevice.xml` — messaging for lost/stolen devices
- `Terminated.xml` — messaging for terminated employee devices
- `SecurityIncident.xml` — messaging for compromised devices

Specify the XML file at runtime using the `-ConfigFile` parameter.

## Packaging for Intune

### Prerequisites

- [Microsoft Win32 Content Prep Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool) (`IntuneWinAppUtil.exe`)
- Access to the Microsoft Intune admin center

### Step 1: Prepare the Source Folder

Ensure the following files are in a single folder:

```
RemoteLock/
├── Invoke-RemoteLockout.ps1
├── RemoteLockout.xml
└── LockScreen.png
```

### Step 2: Create the .intunewin Package

Run the Win32 Content Prep Tool:

```cmd
IntuneWinAppUtil.exe -c "C:\path\to\RemoteLock" -s "Invoke-RemoteLockout.ps1" -o "C:\path\to\output"
```

| Parameter | Value |
|-----------|-------|
| `-c` | Source folder containing all files |
| `-s` | Setup file (the main script) |
| `-o` | Output folder for the `.intunewin` file |

This produces `Invoke-RemoteLockout.intunewin`.

### Step 3: Add the App in Intune

1. Navigate to **Microsoft Intune admin center** > **Apps** > **Windows** > **Add**
2. Select **Windows app (Win32)**
3. Upload `Invoke-RemoteLockout.intunewin`

### Step 4: Configure App Information

| Field | Value |
|-------|-------|
| Name | Remote Lockout |
| Description | Remotely locks a device by taking over the login screen and disabling interactive logon |
| Publisher | IT Security |
| App Version | 1.0 |
| Logo | Upload `RemoteLockout-Logo.png` |

### Step 5: Configure Program Settings

| Field | Value |
|-------|-------|
| Install command | `%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File Invoke-RemoteLockout.ps1 -Mode Install` |
| Uninstall command | `%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File Invoke-RemoteLockout.ps1 -Mode Uninstall` |
| Install behavior | System |
| Device restart behavior | No specific action |

> **For multiple scenarios**, append `-ConfigFile <filename>.xml` to the install command:
> ```
> %SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File Invoke-RemoteLockout.ps1 -Mode Install -ConfigFile LostDevice.xml
> ```

### Step 6: Configure Requirements

| Field | Value |
|-------|-------|
| Operating system architecture | 64-bit |
| Minimum operating system | Windows 10 1903 |

### Step 7: Configure Detection Rules

| Field | Value |
|-------|-------|
| Rule type | File |
| Path | `C:\Windows\IntuneApps\RemoteLockout` |
| File or folder | `TextConfig.json` |
| Detection method | File or folder exists |

### Step 8: Assign the App

- **Do NOT assign to all devices** — this is a targeted lockout tool
- Create a dynamic or static device group for devices that need to be locked
- Assign the app as **Required** to that group
- To unlock: remove the device from the group (triggers uninstall) or assign the uninstall

## Logging

All operations are logged to:

- **Console** — visible during manual execution
- **File** — `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RemoteLockout.log`

Log entries include timestamps and severity levels (Info, Warning, Error).

## Unlocking a Device

To restore normal login functionality:

1. **Via Intune**: Remove the device from the assigned group, or change the assignment to **Uninstall**
2. **Locally** (if physical access): Boot to Safe Mode with Command Prompt and run:
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File "C:\Windows\IntuneApps\RemoteLockout\Invoke-RemoteLockout.ps1" -Mode Uninstall
   ```

## Security Considerations

- The script runs as **SYSTEM** — it has full control over local accounts and security policy
- Backup files are stored in `C:\Windows\IntuneApps\RemoteLockout\Backup` for rollback
- The lockout is multi-layered: disabled accounts + denied logon rights + hidden user list
- Even if someone dismisses the legal notice, authentication will fail
- The staging directory (`C:\Windows\IntuneApps`) is protected by default OS permissions
