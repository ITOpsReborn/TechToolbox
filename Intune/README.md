# Intune Toolbox

This folder contains PowerShell scripts and tools for managing Microsoft Intune.

## Prerequisites

- PowerShell 7.0 or later
- Microsoft Graph PowerShell SDK
  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  ```
- Intune Administrator role or equivalent permissions

## Authentication

Before running any scripts, authenticate to Microsoft Graph:

```powershell
Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All", "DeviceManagementApps.ReadWrite.All"
```

## Folder Structure

- **Administration/** - Diagnostic and reporting tools
  - `RSOP.DEV/Get-RSOPIntune.ps1` - Resultant Set of Policy for Intune
  - `RSOP.DEV/Get-RSOPIntuneGraph.ps1` - RSOP via Microsoft Graph API
- **Applications/** - Application deployment and management scripts
  - `Get-AppDeploymentStatus.ps1` - Monitor application deployment status
  - `RemoteLock/Invoke-RemoteLockout.ps1` - Win32 app that locks out a device (custom lock screen, disables logon, logs off sessions)
- **Devices/** - Device management and inventory scripts
  - `Get-IntuneDeviceInventory.ps1` - Device inventory with compliance status
  - `Sync-IntuneDevices.ps1` - Trigger device sync operations
- **Policies/** - Configuration policy management scripts
  - `Export-IntunePolicies.ps1` - Backup configuration and compliance policies
- **Remediation/** - Detect/remediate script pairs for local configuration issues
  - `AutomaticUpdates/` - Detect and remediate Automatic Updates GPO policy
  - `BitlockerAADBackup/` - Detect and remediate BitLocker AAD key backup
  - `ConnectedUserExperiences/` - Detect and remediate DiagTrack service startup
  - `DeclaredConfigurationCleanup/` - Clean up declared configuration artifacts
  - `PassportForWork/` - Detect and remediate WHfB GPO tattoos
  - `SecureBootCertUpdate/` - Detect and remediate Secure Boot update settings
  - `WindowsUpdateGPOSettings/` - Detect and remediate Windows Update GPO settings
- **Scripts/** - Intune platform scripts deployed to managed devices
  - `Disable-DeliveryOptimizationVerboseLogs.ps1` - Disable DO verbose logging
  - `Disable-LocalUserAccounts.ps1` - Disable all local accounts except LAPS
  - `Enable-DeliveryOptimizationVerboseLogs.ps1` - Enable DO verbose logging
  - `Install-ProvisioningPacakge.ps1` - Install a provisioning package
  - `Install-ProvisioningPacakgeWithOutRippling.ps1` - Install provisioning package (Rippling exclusion)
  - `Install-WindowsFonts.ps1` - Install custom Windows fonts
  - `Inovke-WindowsUpdateRepair.ps1` - Repair Windows Update components
  - `Revoke-WHfBCredentials.ps1` - Remove all WHfB credentials, trigger Intune sync, log off sessions, and reboot

## Common Tasks

### Device Management
- Get device inventory reports
- Sync devices
- Retire or wipe devices
- Assign device configurations

### Policy Management
- Export and import policies
- Create compliance policies
- Manage configuration profiles
- Device restriction policies

### Application Management
- Deploy applications
- Monitor app installation status
- Manage app protection policies
- Update application assignments

### Remediation
- Detect and remediate local configuration issues left by legacy GPOs or misconfigurations
- Typical tasks: remove residual GPO registry settings, enable BitLocker AAD backup, fix SecureBoot settings
- Detection scripts exit `0` when compliant and `1` when remediation is required
- Remediation scripts exit `0` on success and `1` on error

## Best Practices

1. Test policy changes in a pilot group first
2. Use naming conventions for policies and configurations
3. Document all policy purposes and assignments
4. Regular backups of policy configurations
5. Monitor compliance reports regularly
6. Use filters for targeted deployments

## Additional Resources

- [Microsoft Intune Documentation](https://learn.microsoft.com/en-us/mem/intune/)
- [Microsoft Graph Intune API](https://learn.microsoft.com/en-us/graph/api/resources/intune-graph-overview)
- [Intune PowerShell Samples](https://github.com/microsoftgraph/powershell-intune-samples)
