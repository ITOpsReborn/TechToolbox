<#
.SYNOPSIS
    Installs all .otf and .ttf font files from the script's directory.

.DESCRIPTION
    This script scans the directory where it resides for OpenType (.otf) and TrueType (.ttf)
    font files and installs them to the Windows Fonts directory (C:\Windows\Fonts). Each font
    is also registered in the system registry so it persists across reboots. The script provides
    detailed output for each font processed, including success and failure reporting, and returns
    a summary of the installation results.

.EXAMPLE
    .\Install-WindowsFonts.ps1
    Installs all .otf and .ttf fonts found in the same directory as the script.

.NOTES
    Author  : Tim Knapp (Microsoft)
    Date    : 2026-03-03
    Version : 1.0
    Requires: Administrator privileges
#>

[CmdletBinding()]
param ()

# Windows Fonts directory and registry path
$FontsFolder = "$env:SystemRoot\Fonts"
$FontRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"

# Counters for summary
$installed = 0
$skipped = 0
$failed = 0

try {
    # Gather all .otf and .ttf files in the script's directory
    $fontFiles = Get-ChildItem -Path $PSScriptRoot -Include '*.otf', '*.ttf' -File -Recurse:$false

    if (-not $fontFiles -or $fontFiles.Count -eq 0) {
        Write-Warning "No .otf or .ttf font files found in: $PSScriptRoot"
        exit 0
    }

    Write-Output "Found $($fontFiles.Count) font file(s) to process in: $PSScriptRoot"
    Write-Output ('-' * 60)

    foreach ($fontFile in $fontFiles) {
        try {
            $fontName = $fontFile.Name
            $destinationPath = Join-Path -Path $FontsFolder -ChildPath $fontName

            # Determine the registry display name and type suffix
            switch ($fontFile.Extension.ToLower()) {
                '.ttf' { $registrySuffix = '(TrueType)' }
                '.otf' { $registrySuffix = '(OpenType)' }
            }

            # Use the Shell.Application COM object to read the font's display name
            $shellFolder = (New-Object -ComObject Shell.Application).Namespace($fontFile.DirectoryName)
            $shellFile = $shellFolder.ParseName($fontFile.Name)
            # Property index 21 is the font Title
            $fontTitle = $shellFolder.GetDetailsOf($shellFile, 21)

            if ([string]::IsNullOrWhiteSpace($fontTitle)) {
                $fontTitle = [System.IO.Path]::GetFileNameWithoutExtension($fontName)
            }

            $registryName = "$fontTitle $registrySuffix"

            # Check if font is already installed
            if ((Test-Path -Path $destinationPath) -and (Get-ItemProperty -Path $FontRegistryPath -Name $registryName -ErrorAction SilentlyContinue)) {
                Write-Output "[SKIPPED] $fontName - already installed."
                $skipped++
                continue
            }

            # Copy font file to the Windows Fonts directory
            Copy-Item -Path $fontFile.FullName -Destination $destinationPath -Force -ErrorAction Stop

            # Register the font in the registry
            New-ItemProperty -Path $FontRegistryPath -Name $registryName -Value $fontName -PropertyType String -Force -ErrorAction Stop | Out-Null

            Write-Output "[INSTALLED] $fontName -> $registryName"
            $installed++
        }
        catch {
            Write-Error "[FAILED] $($fontFile.Name) - $($_.Exception.Message)"
            $failed++
        }
    }

    # Print summary
    Write-Output ('-' * 60)
    Write-Output "Installation Summary"
    Write-Output "  Installed : $installed"
    Write-Output "  Skipped   : $skipped"
    Write-Output "  Failed    : $failed"
    Write-Output "  Total     : $($fontFiles.Count)"

    if ($failed -gt 0) {
        exit 1
    }

    exit 0
}
catch {
    Write-Error "An unexpected error occurred: $($_.Exception.Message)"
    exit 1
}
