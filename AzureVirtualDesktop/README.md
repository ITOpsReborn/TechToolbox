# Azure Virtual Desktop (AVD) Toolbox

This folder contains PowerShell scripts and tools for managing Azure Virtual Desktop.

## Prerequisites

- PowerShell 7.0 or later
- Azure PowerShell modules
  ```powershell
  Install-Module Az.Accounts, Az.DesktopVirtualization, Az.Resources -Scope CurrentUser
  ```
- Appropriate Azure RBAC roles (Desktop Virtualization Contributor or higher)

## Authentication

Before running any scripts, authenticate to Azure:

```powershell
Connect-AzAccount
```

To work with a specific subscription:
```powershell
Set-AzContext -SubscriptionId "your-subscription-id"
```

## Folder Structure

- **SessionHosts/** - Session host management and monitoring scripts
- **HostPools/** - Host pool configuration and management scripts
- **UserSessions/** - User session management scripts

## Common Tasks

### Session Host Management
- Monitor session host health and status
- Drain session hosts for maintenance
- Start/stop session hosts for cost optimization
- Scale session hosts dynamically

### Host Pool Management
- Create and configure host pools
- Manage load balancing settings
- Configure validation environments
- Export host pool configurations

### User Session Management
- View active user sessions
- Send messages to users
- Log off or disconnect users
- Monitor session resource usage

## Key Concepts

### Host Pool Types
- **Pooled** - Multiple users share VMs (recommended for most scenarios)
- **Personal** - Each user gets a dedicated VM

### Load Balancing Algorithms
- **Breadth-first** - Distribute users evenly across session hosts
- **Depth-first** - Fill one session host before moving to the next

### Session Host States
- **Available** - Ready to accept connections
- **Unavailable** - Cannot accept new connections
- **NeedsAssistance** - Requires attention
- **Shutdown** - Powered off
- **Disconnected** - Lost connection to Azure

## Best Practices

1. Use Azure Monitor for AVD insights
2. Implement auto-scaling for cost optimization
3. Regular session host image updates
4. Configure drain mode before maintenance
5. Monitor user experience with Log Analytics
6. Use validation host pools for testing
7. Implement proper RBAC and network security
8. Regular backup of host pool configurations

## Cost Optimization

- Stop session hosts during off-hours
- Use auto-scaling based on user demand
- Right-size VMs based on workload
- Use Azure Reserved Instances for predictable workloads
- Monitor and optimize storage costs

## Troubleshooting

- Check session host agent health
- Verify network connectivity (RDP, Azure endpoints)
- Review Azure Monitor logs
- Check host pool diagnostic settings
- Validate user permissions and assignments

## Additional Resources

- [Azure Virtual Desktop Documentation](https://learn.microsoft.com/en-us/azure/virtual-desktop/)
- [AVD PowerShell Reference](https://learn.microsoft.com/en-us/powershell/module/az.desktopvirtualization/)
- [AVD Architecture](https://learn.microsoft.com/en-us/azure/architecture/example-scenario/wvd/windows-virtual-desktop)
