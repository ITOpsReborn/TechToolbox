<#
.SYNOPSIS
    Installs a Windows provisioning package (.ppkg) silently and forcefully.

.DESCRIPTION
    This script installs a specified Windows provisioning package (.ppkg) using the
    Install-ProvisioningPackage cmdlet. It runs silently with the -ForceInstall flag
    to bypass any user prompts. The provisioning package file is expected to reside
    in the same directory as the script by default, but a custom path can be provided.

.PARAMETER PackageName
    The file name of the provisioning package (e.g. "MyConfig.ppkg").

.PARAMETER PackagePath
    The directory path where the provisioning package is located.
    Defaults to the script's root directory ($PSScriptRoot).

.EXAMPLE
    .\Install-ProvisioningPacakge.ps1 -PackageName "MyConfig.ppkg"
    Installs the provisioning package from the script's directory.

.EXAMPLE
    .\Install-ProvisioningPacakge.ps1 -PackageName "MyConfig.ppkg" -PackagePath "C:\Packages"
    Installs the provisioning package from the specified directory.

.NOTES
    Author  : Tim Knapp (Microsoft)
    Date    : 2026-03-03
    Version : 1.0
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "The file name of the provisioning package (.ppkg) to install.")]
    [ValidateNotNullOrEmpty()]
    [string]$PackageName,

    [Parameter(Mandatory = $false, HelpMessage = "The directory containing the provisioning package. Defaults to the script root.")]
    [ValidateNotNullOrEmpty()]
    [string]$PackagePath = $PSScriptRoot
)

# Build the full path to the provisioning package
$PackageFullPath = Join-Path -Path $PackagePath -ChildPath $PackageName

try {
    # Verify the provisioning package file exists
    if (-not (Test-Path -Path $PackageFullPath -PathType Leaf)) {
        throw "Provisioning package not found: $PackageFullPath"
    }

    # Verify the file has a .ppkg extension
    if ([System.IO.Path]::GetExtension($PackageFullPath) -ne '.ppkg') {
        throw "The specified file is not a provisioning package (.ppkg): $PackageName"
    }

    Write-Output "Installing provisioning package: $PackageFullPath"

    # Install the provisioning package silently and forcefully
    Install-ProvisioningPackage -PackagePath $PackageFullPath -ForceInstall -QuietInstall -ErrorAction Stop

    Write-Output "Provisioning package installed successfully."
    exit 0
}
catch {
    Write-Error "Failed to install provisioning package. Error: $($_.Exception.Message)"
    exit 1
}
