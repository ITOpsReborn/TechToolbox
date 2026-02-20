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

- **Devices/** - Device management and inventory scripts
- **Policies/** - Configuration policy management scripts
- **Applications/** - Application deployment and management scripts
 - **Remediation/** - Scripts to detect and remediate local configuration issues (GPO remnants, SecureBoot settings, BitLocker AAD backups, etc.)

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
