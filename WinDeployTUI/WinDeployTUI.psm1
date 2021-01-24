function Start-WDT {
	if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
		Write-Error 'Start in elevated PowerShell session'
		break
	}

	if ($PSVersionTable.PSEdition -ne 'Core'){
		if (Get-Command -Name 'pwsh.exe' -ErrorAction SilentlyContinue){
			pwsh.exe -Command "Import-Module '$PSScriptRoot'; Start-WDT"
			break
		}
	}

	$Info = Get-WDTClientInfo
	$ModuleVersion = $MyInvocation.MyCommand.Module.Version

	while ($true){
		$WaitCleanConsole = $true
		Clear-Host

		Write-Host
		Write-Host "  || -- Windows Deployment TUI v$ModuleVersion -- ||" -ForegroundColor Magenta
		Write-Host
		Write-Host "  Windows $($Info.WinVersion) - $($Info.Architecture) - $($Info.ProductType) - PowerShell $($Info.PSVersion)"
		Write-Host "  System: $($Info.Model)"
		Write-Host
		Write-Host "   - GENERAL -" -ForegroundColor Yellow
		Write-Host "  1. Install WDT requirements"
		Write-Host "  2. Generic settings (taskbar)"
		Write-Host "  3. Install and reload in PowerShell Core"
		Write-Host "  4. Install TightVNC server"
		Write-Host "  5. Install programs with ChocolateyGet"
		Write-Host "  9. Uninstall TightVNC server"
		Write-Host
		Write-Host "   - OPTIONAL -" -ForegroundColor Yellow
		Write-Host "  a. Install Chocolatey (choco.exe)"
		Write-Host "  b. Remove Appx packages (current user)"
		Write-Host
		Write-Host "  q. Quit" -ForegroundColor Red
		Write-Host
		
		$Choice = Read-Host "  Choice"
		Write-Host
		
		switch ($Choice) {
			1 { Install-WDTRequirements -PSVersion $Info.PSVersion }
			2 { Set-WDTGeneralSettings -WinVersion $Info.WinVersion }
			3 {
				if (Test-Path "$env:ProgramFiles\PowerShell\*\pwsh.exe"){
					Write-Warning 'PowerShell Core already installed'
				}
				else {
					Write-WDTStatus 'Install PowerShell Core'
					Install-Package -Name 'powershell-core' -ProviderName ChocolateyGet -Force | Out-Null
					Write-WDTStatus 'Done'
				}

				$CoreExe = Get-Item "$env:ProgramFiles\PowerShell\*\pwsh.exe"
				if ($CoreExe){
					. $CoreExe -Command "Import-Module '$PSScriptRoot'; Start-WDT"
					return
				}
			}
			4 {
				if (Find-WDTChocoGet){
					Write-WDTStatus 'Install TightVNC Server'
					Install-Package -Name 'tightvnc' -ProviderName ChocolateyGet -AdditionalArguments '--installarguments "ADDLOCAL=Server VALUE_OF_ACCEPTHTTPCONNECTIONS=0 SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=0 SET_PASSWORD=1 VALUE_OF_PASSWORD="' -Force | Out-Null
					Write-WDTStatus 'Done'
				}
			}
			5 {
				if (Find-WDTChocoGet){
					$Packages = Read-WDTChocoPackages

					if ($Packages){
						Install-WDTChocoPackages -Packages $Packages
					}
					else {
						$WaitCleanConsole = $false
					}
				}
			}
			9 {
				if (Find-WDTChocoGet){
					Write-WDTStatus 'Uninstall TightVNC Server'
					Get-PackageProvider -Name ChocolateyGet | Out-Null
					Uninstall-Package -Name 'tightvnc' -ProviderName ChocolateyGet | Out-Null
					Write-WDTStatus 'Done'
				}
			}

			a { Install-WDTChoco }
			b { $WaitCleanConsole = Remove-WDTAppx -WinVersion $Info.WinVersion }
			q {
				return
			}
			default { Write-Warning "Type a digit or a letter" }
		}
		
		if ($WaitCleanConsole){
			Write-Host
			Read-Host "Press enter to return to menu"
		}
	}
}

function Write-WDTStatus {
	param ($Text)

	Write-Host "$(Get-Date -Format 'HH:mm:ss') $Text" -ForegroundColor Green
}

function Install-WDTRequirements {
	param ($PSVersion)

	if ($PSVersion -le 5.0){
		Write-Warning 'PowerShell version too old. Install WMF 5.1 or powershell-core with menuoption "a"'
		return
	}

	if ((Get-PSRepository PSGallery).InstallationPolicy -eq 'Untrusted'){
		Write-WDTStatus "Trust PSGallery repo"
		Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
	}

	if ($PSVersionTable.PSEdition -eq 'Core'){
		if (Get-Module -Name 'Microsoft.PowerShell.ConsoleGuiTools' -ListAvailable){
			Write-Warning 'Microsoft.PowerShell.ConsoleGuiTools already installed'
		}
		else {
			Write-WDTStatus "Install ConsoleGuiTools module"
			Install-Module -Name 'Microsoft.PowerShell.ConsoleGuiTools'
		}
	}

	if (Import-Module -Name PackageManagement -MinimumVersion 1.4.7 -ErrorAction SilentlyContinue -PassThru){
		Write-Warning 'PackageManagement => 1.4.7 already installed'
	}
	else {
		Write-WDTStatus "Upgrade PackageManagement module"
		Install-Module PackageManagement -Force
	}

	if (Get-PackageProvider -Name ChocolateyGet -ErrorAction SilentlyContinue){
		Write-Warning 'ChocolateyGet already installed'
	}
	else {
		Write-WDTStatus 'Register Chocolatey repository' -ForegroundColor Green
		Install-PackageProvider ChocolateyGet | Out-Null
	}

	Write-WDTStatus 'Done'
}

function Find-WDTChocoGet {
	if (Get-PackageProvider -Name ChocolateyGet -ErrorAction SilentlyContinue){
		return $true
	}
	else {
		Write-Warning 'ChocolateyGet not installed'
		return $false
	}
}

function Install-WDTChoco {
	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
	(New-Object System.Net.WebClient).DownloadFile('https://chocolatey.org/install.ps1', "$env:TEMP\chocoinstall.ps1")
	. "$env:TEMP\chocoinstall.ps1"
}

function Read-WDTChocoPackages {
	$Packages = Import-Csv "$PSScriptRoot\data\chocopackages.csv"

	$InstalledPackages = Get-Package -ProviderName ChocolateyGet

	foreach ($Package in $Packages){
		if ($InstalledPackages.Name -contains $Package.name){
			$Package | Add-Member -Name Installed -MemberType NoteProperty -Value 'yes'
		} else {
			$Package | Add-Member -Name Installed -MemberType NoteProperty -Value 'no'
		}
	}

	if ($PSVersionTable.PSEdition -eq 'Core'){
		return $Packages | Out-ConsoleGridView -Title 'Select choco packages' -OutputMode Multiple
	} else {
		return $Packages | Out-GridView -PassThru -Title 'Select choco packages'
	}
}

function Install-WDTChocoPackages {
	param ($Packages)

	foreach ($Package in $Packages){
		Write-WDTStatus "Install $($Package.name)"

		if ($Package.arguments){
			Install-Package -Name $Package.name -ProviderName ChocolateyGet -AdditionalArguments "--installarguments '$($Package.arguments)'" -Force | Out-Null
		} else {
			Install-Package -Name $Package.name -ProviderName ChocolateyGet -Force | Out-Null
		}

		if ($Package.selfupdating -eq 'yes'){
			Write-Warning "Run this command to disable choco updates: choco pin add -n=$($Package.name)"
		}
	}
}

function Get-WDTClientInfo {
	[double]$WinVersion = [Environment]::OSVersion.Version.Major.toString() + "." + [Environment]::OSVersion.Version.Minor.toString()
	$OS = Get-CimInstance -ClassName Win32_OperatingSystem

	if ($OS.ProductType -eq 1){
		$ProductType = "client"
	} else {
		$ProductType = "server"
	}

	[double]$PSVersion = $PSVersionTable.PSVersion.Major.ToString() + '.' + $PSVersionTable.PSVersion.Minor.ToString()
	$Model = (Get-CimInstance -ClassName Win32_ComputerSystem).Model

	return [PSCustomObject]@{
		WinVersion = $WinVersion
		Architecture = $OS.OSArchitecture
		ProductType = $ProductType
		PSVersion = $PSVersion
		Model = $Model
	}
}

function Set-WDTGeneralSettings {
	param ($WinVersion)

	if ($WinVersion -ge 6.1){
		Write-WDTStatus "OS >= Win7: Do not combine taskbar buttons"
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 1 -PropertyType 'dword' -Force | Out-Null
	
		Write-WDTStatus "OS >= Win7: Show all notification items"
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | New-ItemProperty -Name "NoAutoTrayNotify" -Value 1 -PropertyType 'dword' | Out-Null
	}

	if ($WinVersion -eq 10.0){
		Write-WDTStatus "OS >= Win10: Hide search bar"
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -PropertyType 'dword' -Force | Out-Null

		Write-WDTStatus "OS >= Win10: Hide Meet Now icon"
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1 -PropertyType 'dword' -Force | Out-Null

		Write-WDTStatus "OS >= Win10: Disable OneDrive"
		Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDrive' -ErrorAction SilentlyContinue | Remove-ItemProperty -Name 'OneDrive'
	}
	
	Write-WDTStatus "Restart explorer.exe"
	Stop-Process -Name explorer
}

function Remove-WDTAppx {
	param ($WinVersion)

	if ($WinVersion -lt 6.3){
		Write-Warning 'Appx packages only applicable and tested on Windows 8.1 and higher'
		return $true
	}
	elseif ($WinVersion -eq 6.3){
		$Apps = Import-Csv "$PSScriptRoot\data\appx-win8.csv"
	}
	elseif ($WinVersion -eq 10.0){
		$Apps = Import-Csv "$PSScriptRoot\data\appx.csv"
	}

	if ($PSVersionTable.PSEdition -eq 'Core'){
		Import-Module Appx -UseWindowsPowerShell -WarningAction SilentlyContinue
	} else {
		Import-Module Appx
	}

	foreach ($App in $Apps){
		if (Get-AppxPackage -Name $App.Name){
			$App | Add-Member -Name Installed -MemberType NoteProperty -Value 'yes'
		} else {
			$App | Add-Member -Name Installed -MemberType NoteProperty -Value 'no'
		}
	}

	if ($PSVersionTable.PSEdition -eq 'Core'){
		$Remove = $Apps | Out-ConsoleGridView -Title 'Select Appx packages' -OutputMode Multiple
	} else {
		$Remove = $Apps | Out-GridView -PassThru -Title 'Select Appx packages'
	}

	if ($Remove){
		foreach ($App in $Remove){
			Write-WDTStatus $App.Name + ' (' + $App.FriendlyName + ')'
			Get-AppxPackage -Name $App.Name | Remove-AppxPackage -Confirm:$false
		}

		return $true
	}
	else {
		return $false
	}
}
