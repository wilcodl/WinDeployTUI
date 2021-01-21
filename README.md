![Windows shield](https://img.shields.io/powershellgallery/p/WinDeployTUI.svg)

# WinDeployTUI
Deployment Text Interface for configuring Windows OS. It currently can do the following things:

* Optimize taskbar
* Silent install and uninstall a VNC server
* Select and install Chocolatey packages
* Remove garbage Appx packages on Win 10

# Download and run latest version

Start PowerShell as Administrator and run the following commands:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Path = (Get-Location).Path
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/wilcodl/WinDeployTUI/archive/master.zip" -OutFile "$Path\master.zip"

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