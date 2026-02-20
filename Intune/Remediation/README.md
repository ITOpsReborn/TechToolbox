# Intune Remediation

This folder contains remediation scripts intended for use with Endpoint Analytics or as standalone fixes.

Subfolders:
- AutomaticUpdates/ - Detect and remove legacy GPO update settings
- BitlockerAADBackup/ - Detect and remediate BitLocker AAD backup configuration
- ConnectedUserExperiences/ - Detect/disable diagnostic tracking artifacts
- DeclaredConfigurationCleanup/ - Standalone cleanup script to remove Declared Configuration artifacts and trigger Intune sync
- PassportForWork/ - Remove WHfB GPO artifacts
- SecureBootCertUpdate/ - Detect and remediate SecureBoot certificate/update settings

Current scripts:
- Standard remediation pairs (detect + remediate):
	- `Detect-*.ps1`
	- `Remediate-*.ps1`
- Standalone cleanup script:
	- `DeclaredConfigurationCleanup/Invoke-DeclaredConfigurationCleanup.ps1`

Usage:
- Detection scripts should exit `0` when compliant and `1` when remediation is required.
- Remediation scripts should exit `0` on success and `1` on error.
- Some scripts may use `2` for unexpected errors.
- `Invoke-DeclaredConfigurationCleanup.ps1` should be run as Administrator.

Place any new remediation scripts in a descriptive subfolder and update this README accordingly.
