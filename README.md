![Windows shield](https://img.shields.io/powershellgallery/p/WinDeployTUI.svg)

# WinDeployTUI
Deployment Text Interface for configuring Windows OS. It currently can do the following things:

* Optimize taskbar
* Silent install and uninstall a VNC server
* Select and install Chocolatey packages
* Remove garbage Appx packages on Win 10

# System requirements

* Windows 7 and higher?
* PowerShell 4.0 and higher?
* User with system admin rights
* Internet connection for installing Chocolatey packages

Tested on OS:

* Windows Server 2012R2 x64
* Windows 8.1 x64
* Windows 10 build 2004 and 20H2

Tested with:

* Windows PowerShell 4.0 (partial functionality)
* Windows PowerShell 5.1
* PowerShell Core 7.1

# Download and run latest version

Start PowerShell as Administrator and run the following commands:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser

$Path = (Get-Location).Path
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/wilcodl/WinDeployTUI/archive/master.zip" -OutFile "$Path\master.zip"
if (Test-Path "$Path\WinDeployTUI-master"){ Remove-Item -Path "$Path\WinDeployTUI-master" -Recurse -Force }

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory("$Path\master.zip", $Path)

Import-Module "$Path\WinDeployTUI-master\WinDeployTUI"
Start-WDT
```

# Install and run stable version

Start PowerShell as Administrator and run the following commands:

```powershell
Install-Module WinDeployTUI
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser

Import-Module WinDeployTUI
Start-WDT
```