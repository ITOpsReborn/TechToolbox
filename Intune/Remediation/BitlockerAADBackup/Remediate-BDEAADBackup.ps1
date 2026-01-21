#   Remediation script to to backup BitLocker Recovery keys
#   to AAD to include multiple disk if encrypted.
#   Remediate-BDEAADBackup.ps1
#   Author: Tim Knapp
#           Larry Kleist

#   Change History
#   1.0 (2022-OCT-25):
#       - First release
#   1.5 (2022-OCT-27):
#       - Add multiple disk if encrypted

try{
    $BitlockerVols = Get-Bitlockervolume
     ForEach ($BitlockerVol in $BitlockerVols ){
         if($BitlockerVol.ProtectionStatus -eq 'On' -and $BitlockerVol.EncryptionPercentage -eq '100'){
           $KPID=""
                foreach($KP in $BitlockerVol.KeyProtector){
                  if($KP.KeyProtectorType -eq "RecoveryPassword"){
                        $KPID=$KP.KeyProtectorId
             }    
         }
           BackupToAAD-BitLockerKeyProtector -MountPoint "$($BitlockerVol.MountPoint)" -KeyProtectorId $KPID
         }
    }
     Write-Output "Backup complete"
     Exit 0
   }
   catch{
    Write-Error "Error: $($_)"
     Exit 1
   }