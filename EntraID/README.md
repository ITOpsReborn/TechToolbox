# Entra ID (Azure AD) Toolbox

This folder contains PowerShell scripts and tools for managing Microsoft Entra ID (formerly Azure Active Directory).

## Prerequisites

- PowerShell 7.0 or later
- Microsoft Graph PowerShell SDK
  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  ```
- Appropriate permissions in Entra ID

## Authentication

Before running any scripts, authenticate to Microsoft Graph:

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess"
```

## Folder Structure

- **Users/** - User management scripts
- **Groups/** - Group management scripts
- **ConditionalAccess/** - Conditional Access policy management scripts

## Common Tasks

### User Management
- Create bulk users
- Export user reports
- Update user properties
- Manage user licenses

### Group Management
- Create and manage security groups
- Dynamic group management
- Group membership operations

### Conditional Access
- Export existing policies
- Create policy templates
- Manage policy assignments

## Best Practices

1. Always test scripts in a development/test environment first
2. Use service principals for automation
3. Implement proper error handling
4. Log all operations for audit purposes
5. Follow the principle of least privilege

## Additional Resources

- [Microsoft Graph PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
- [Entra ID Documentation](https://learn.microsoft.com/en-us/entra/identity/)
