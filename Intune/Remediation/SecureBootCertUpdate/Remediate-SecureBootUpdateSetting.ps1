#   Remediate-SecureBootUpdateSetting.ps1
#   Function: Ensure the SecureBoot "AvailableUpdates" DWORD equals 0x5944
#             under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot
#
#   Author: Tim Knapp
#
#   Change History
#   1.0 (2026-JAN-21):
#       - Initial release

[string]$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
[string]$regKeyName = "AvailableUpdates"

try {
	# If the registry path doesn't exist, create it first
	if (-not (Test-Path -Path $regPath)) {
		New-Item -Path $regPath -Force | Out-Null
	}
	# Check whether the property already exists
	$prop = Get-ItemProperty -Path $regPath -Name $regKeyName -ErrorAction SilentlyContinue

	if ($null -ne $prop)
	{
		# Property exists — compare value
		$current = $prop.$regKeyName
		if ($current -eq 0x5944)
		{
			# Already set correctly
			exit 0
		}
		else {
			# Update existing property value
			Set-ItemProperty -Path $regPath -Name $regKeyName -Value 0x5944 -ErrorAction Stop
			exit 0
		}
	}
	else {
		# Property does not exist — create it
		New-ItemProperty -Path $regPath -Name $regKeyName -PropertyType DWord -Value 0x5944 -Force | Out-Null
		exit 0
	}
}
catch {
	$errMsg = $_.Exception.Message
	Write-Error $errMsg
	exit 1
}

