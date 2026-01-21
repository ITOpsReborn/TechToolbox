#   Detection script to determine if the event for BDE to
#   backup recovery key to AAD has occurred

#   Detect-BDEAADBackup.ps1

#   Author: Tim Knapp

#   Change History
#   1.0 (2022-OCT-25):
#       - First release

$provider = "Microsoft-Windows-BitLocker-API"
$eventID = "845"

try {
    $event = Get-WinEvent -ProviderName $provider | Where-Object {$_.Id -eq $eventID}
    if($event)
    {
        Write-Output "AAD backup has occurred"
        Exit 0
    }
    else {
        Write-Error "AAD backup has NOT occurred"
        Exit 1
    }
}
catch {
    Write-Error "Error reading event, assuming non-compliance"
    Exit 1
}