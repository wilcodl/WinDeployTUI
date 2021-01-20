# WinDeployTUI
Deployment Text Interface for configuring Windows OS

# Download and run through Github
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/wilcodl/WinDeployTUI/archive/master.zip" -OutFile '.\master.zip'

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory('.\master.zip', '.\')
Move-Item -Path .\WinDeployTUI-master -Destination .\WinDeployTUI

Import-Module .\WinDeployTUI
Start-WDT
```