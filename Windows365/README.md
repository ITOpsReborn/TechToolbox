# Windows 365 Toolbox

This folder contains PowerShell scripts and tools for managing Windows 365 Cloud PCs.

## Prerequisites

- PowerShell 7.0 or later
- Microsoft Graph PowerShell SDK
  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  ```
- Windows 365 Administrator or Cloud PC Administrator role

## Authentication

Before running any scripts, authenticate to Microsoft Graph:

```powershell
Connect-MgGraph -Scopes "CloudPC.ReadWrite.All", "DeviceManagementConfiguration.Read.All"
```

## Folder Structure

- **CloudPCs/** - Cloud PC management and monitoring scripts
- **Provisioning/** - Provisioning policy and configuration scripts

## Common Tasks

### Cloud PC Management
- Monitor Cloud PC status and health
- Export Cloud PC inventory
- Perform remote actions (restart, reprovision)
- End grace period for Cloud PCs

### Provisioning Management
- Create and manage provisioning policies
- Configure Azure network connections
- Monitor provisioning status
- Manage user settings policies

## Key Concepts

### Cloud PC Lifecycle
1. **Provisioning** - Cloud PC is created and configured
2. **Provisioned** - Cloud PC is ready for use
3. **In Grace Period** - User license removed, 7-day grace period
4. **Deprovisioning** - Cloud PC being removed
5. **Failed** - Provisioning or operation failed

### Provisioning Policies
Define the configuration for Cloud PCs including:
- Image selection
- Network configuration
- Size/SKU selection
- User assignment

### Azure Network Connections
- Connect Cloud PCs to your Azure virtual network
- Enable on-premises resource access
- Configure hybrid join settings

## Best Practices

1. Use dedicated Azure network connections for Cloud PCs
2. Implement proper RBAC for Cloud PC management
3. Monitor provisioning failures and address promptly
4. Plan for adequate IP address space
5. Regular health checks of Azure network connections
6. Use filters for targeted policy assignments
7. Document provisioning policies and configurations

## Troubleshooting

- Check Azure network connection health status
- Review provisioning policy assignments
- Verify user licenses (Windows 365 Enterprise/Business)
- Check Intune device records
- Review audit logs for provisioning failures

## Additional Resources

- [Windows 365 Documentation](https://learn.microsoft.com/en-us/windows-365/)
- [Windows 365 Enterprise Planning](https://learn.microsoft.com/en-us/windows-365/enterprise/)
- [Microsoft Graph CloudPC API](https://learn.microsoft.com/en-us/graph/api/resources/cloudpc-api-overview)
