# TechToolbox

A comprehensive collection of PowerShell scripts and tools for managing Microsoft cloud services including Entra ID, Intune, Windows 365, and Azure Virtual Desktop.

## 📋 Overview

This toolbox provides IT administrators and engineers with ready-to-use PowerShell scripts to automate common management tasks across Microsoft's modern workplace platforms. Each tool is designed to be production-ready with proper error handling, logging, and parameter validation.

## 🗂️ Repository Structure

```
TechToolbox/
├── EntraID/                    # Microsoft Entra ID (Azure AD) Management
│   ├── Users/                  # User management scripts
│   ├── Groups/                 # Group management scripts
│   ├── ConditionalAccess/      # Conditional Access policy scripts
│   └── README.md
├── Intune/                     # Microsoft Intune Management
│   ├── Administration/         # RSOP and diagnostic tools
│   ├── Applications/           # Application deployment and Remote Lockout
│   ├── Devices/                # Device inventory and management
│   ├── Policies/               # Configuration policy management
│   ├── Remediation/            # Detect and remediate local configuration issues
│   ├── Scripts/                # Platform scripts for Intune-managed devices
│   └── README.md
├── Windows365/                 # Windows 365 Cloud PC Management
│   ├── CloudPCs/               # Cloud PC operations
│   ├── Provisioning/           # Provisioning policy management
│   └── README.md
└── AzureVirtualDesktop/        # Azure Virtual Desktop Management
    ├── SessionHosts/           # Session host management
    ├── HostPools/              # Host pool configuration
    ├── UserSessions/           # User session management
    └── README.md
```

## 🚀 Getting Started

### Prerequisites

1. **PowerShell 7.0 or later**
   ```powershell
   # Check your PowerShell version
   $PSVersionTable.PSVersion
   ```

2. **Required PowerShell Modules**
   ```powershell
   # For Entra ID and Intune
   Install-Module Microsoft.Graph -Scope CurrentUser
   
   # For Azure Virtual Desktop
   Install-Module Az.Accounts, Az.DesktopVirtualization, Az.Resources -Scope CurrentUser
   ```

3. **Administrative Permissions**
   - Appropriate roles in Microsoft Entra ID
   - Intune Administrator or equivalent
   - Windows 365 Administrator (for Cloud PCs)
   - Desktop Virtualization Contributor (for AVD)

### Authentication

**For Entra ID, Intune, and Windows 365:**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All", "DeviceManagementManagedDevices.ReadWrite.All"
```

**For Azure Virtual Desktop:**
```powershell
# Connect to Azure
Connect-AzAccount
Set-AzContext -SubscriptionId "your-subscription-id"
```

## 📦 Components

### 🔐 Entra ID (Azure AD)

Manage users, groups, and conditional access policies in Microsoft Entra ID.

**Key Scripts:**
- `Get-EntraIDUserReport.ps1` - Export comprehensive user reports
- `New-BulkUsers.ps1` - Create multiple users from CSV
- `New-EntraIDGroup.ps1` - Create security/Microsoft 365 groups
- `Export-GroupMemberships.ps1` - Export all groups and memberships
- `Export-ConditionalAccessPolicies.ps1` - Backup conditional access policies

[📖 View Entra ID Documentation](./EntraID/README.md)

### 📱 Intune

Manage devices, policies, and applications in Microsoft Intune.

**Key Scripts:**
- `Get-IntuneDeviceInventory.ps1` - Device inventory with compliance status
- `Sync-IntuneDevices.ps1` - Trigger device sync operations
- `Export-IntunePolicies.ps1` - Backup configuration and compliance policies
- `Get-AppDeploymentStatus.ps1` - Monitor application deployment
- `Invoke-RemoteLockout.ps1` - Remote device lockdown via Intune Win32 app (lost/stolen/terminated scenarios)
- `Get-RSOPIntune.ps1` / `Get-RSOPIntuneGraph.ps1` - Resultant Set of Policy for Intune
- `Invoke-DeclaredConfigurationCleanup.ps1` - Remove Declared Configuration artifacts and trigger Intune sync
- `Remediation/` - Detection and remediation script pairs (AutomaticUpdates, BitLocker AAD Backup, Connected User Experiences, PassportForWork, SecureBoot Cert Update, Windows Update GPO Settings)
- `Scripts/` - Intune platform scripts (credential revocation, font installs, provisioning packages, delivery optimization, Windows Update repair, local account management, and more)

[📖 View Intune Documentation](./Intune/README.md)

### ☁️ Windows 365

Manage Windows 365 Cloud PCs and provisioning policies.

**Key Scripts:**
- `Get-CloudPCInventory.ps1` - Cloud PC inventory and health
- `Invoke-CloudPCAction.ps1` - Remote actions (restart, reprovision)
- `Export-ProvisioningPolicies.ps1` - Backup provisioning configurations

[📖 View Windows 365 Documentation](./Windows365/README.md)

### 🖥️ Azure Virtual Desktop

Manage Azure Virtual Desktop host pools, session hosts, and user sessions.

**Key Scripts:**
- `Get-AVDSessionHostInventory.ps1` - Session host inventory and status
- `Set-DrainMode.ps1` - Enable/disable drain mode for maintenance
- `Export-HostPoolConfiguration.ps1` - Backup host pool configurations
- `Get-UserSessions.ps1` - Monitor active user sessions

[📖 View Azure Virtual Desktop Documentation](./AzureVirtualDesktop/README.md)

## 💡 Usage Examples

### Export All Users from Entra ID
```powershell
cd EntraID/Users
.\Get-EntraIDUserReport.ps1 -OutputPath "C:\Reports\Users.csv"
```

### Get Intune Device Inventory
```powershell
cd Intune/Devices
.\Get-IntuneDeviceInventory.ps1 -IncludeNonCompliant
```

### Monitor Cloud PC Status
```powershell
cd Windows365/CloudPCs
.\Get-CloudPCInventory.ps1 -IncludeHealthChecks
```

### Set Session Host to Drain Mode
```powershell
cd AzureVirtualDesktop/SessionHosts
.\Set-DrainMode.ps1 -HostPoolName "HP-Production" -ResourceGroupName "RG-AVD" -SessionHostNames @("sh-001") -EnableDrainMode
```

## 🛡️ Best Practices

1. **Test in Non-Production First** - Always test scripts in a development/test environment
2. **Use Least Privilege** - Apply minimum required permissions for each task
3. **Implement Logging** - Enable audit logging for all operations
4. **Backup Before Changes** - Export configurations before making changes
5. **Use Service Principals** - For automation, use service principals with appropriate permissions
6. **Version Control** - Keep track of script versions and changes
7. **Documentation** - Document custom modifications and use cases

## 🔒 Security Considerations

- Never hard-code credentials in scripts
- Use Azure Key Vault or credential managers for sensitive data
- Implement proper RBAC (Role-Based Access Control)
- Regular review of permissions and access
- Enable MFA for administrative accounts
- Monitor audit logs for suspicious activities

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:
1. Test your scripts thoroughly
2. Include proper parameter validation and error handling
3. Add comment-based help to all scripts
4. Update relevant README files
5. Follow PowerShell best practices and coding standards

## 📄 License

This project is provided as-is for use within organizations managing Microsoft cloud services.

## 🆘 Support and Resources

### Microsoft Documentation
- [Microsoft Graph PowerShell](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
- [Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/)
- [Microsoft Intune](https://learn.microsoft.com/en-us/mem/intune/)
- [Windows 365](https://learn.microsoft.com/en-us/windows-365/)
- [Azure Virtual Desktop](https://learn.microsoft.com/en-us/azure/virtual-desktop/)

### Community Resources
- [Microsoft Tech Community](https://techcommunity.microsoft.com/)
- [PowerShell Gallery](https://www.powershellgallery.com/)

## 📝 Changelog
### Version 1.1.0
- Added Intune Administration tools (RSOP.DEV)
- Added Intune platform scripts: Revoke-WHfBCredentials, Disable-LocalUserAccounts, Install-WindowsFonts, Install-ProvisioningPackage, Enable/Disable-DeliveryOptimizationVerboseLogs, Invoke-WindowsUpdateRepair, Revoke-WHfBCredentials
- Added Intune remediation script pairs: AutomaticUpdates, BitlockerAADBackup, ConnectedUserExperiences, DeclaredConfigurationCleanup, PassportForWork, SecureBootCertUpdate, WindowsUpdateGPOSettings

### Version 1.0.0 (Initial)
- Entra ID management scripts (Users, Groups, Conditional Access)
- Intune management scripts (Devices, Policies, Applications)
- Windows 365 management scripts (Cloud PCs, Provisioning)
- Azure Virtual Desktop management scripts (Session Hosts, Host Pools, User Sessions)
### Version 1.0.1 (2026-01-21)
- Added Intune `Remediation/` folder, `Intune/Remediation/README.md`, and SecureBoot detection/remediation scripts

---

**Note:** This toolbox is designed for IT professionals managing Microsoft cloud services. Ensure you have appropriate permissions and understanding before running scripts in production environments.