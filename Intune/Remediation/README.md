# Intune Remediation

This folder contains remediation scripts intended for use with Endpoint Analytics or as standalone fixes.

Subfolders:
- AutomaticUpdates/ - Detect and remove legacy GPO update settings
- BitlockerAADBackup/ - Detect and remediate BitLocker AAD backup configuration
- ConnectedUserExperiences/ - Detect/disable diagnostic tracking artifacts
- PassportForWork/ - Remove WHfB GPO artifacts
- SecureBootCertUpdate/ - Detect and remediate SecureBoot certificate/update settings

Usage:
- Detection scripts should exit `0` when compliant and `1` when remediation is required.
- Remediation scripts should exit `0` on success and `1` on error.

Place any new remediation scripts in a descriptive subfolder and update this README accordingly.
