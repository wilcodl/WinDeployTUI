# WinDeployTUI
Deployment Text Interface for configuring Windows OS

# Installation through Github
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/wilcodl/WinDeployTUI/archive/master.zip" -OutFile '.\master.zip'

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory('.\master.zip', '.\')

Import-Module .\WinDeployTUI-master\WinDeployTUI.psd1
```