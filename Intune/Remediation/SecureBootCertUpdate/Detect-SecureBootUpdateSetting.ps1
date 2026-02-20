#   Detect-SecureBootUpdateSetting.ps1
#   Function: Detect whether the SecureBoot "AvailableUpdates" DWORD
#             equals 0x5944 under
#             HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot
#
#   Author: Tim Knapp
#
#   Change History
#   1.0 (2026-JAN-21):
#       - Initial release

[string]$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
[string]$regKeyName = "AvailableUpdates"

try {
	$test = Get-ItemProperty -Path $regPath -ErrorAction Stop

	if ($test.PSObject.Properties.Name -contains $regKeyName)
	{
		$value = $test.$regKeyName

		if ($value -eq 0x5944)
		{
			Write-Host "Match"
			Exit 0
		}
		else {
			Write-Host "No_Match"
			Exit 1
		}
	}
	else {
		Write-Host "No_Match"
		Exit 1
	}
}
catch {
	Write-Host "No_Match"
	Exit 1
}

