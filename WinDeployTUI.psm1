function Start-WDT {
	if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
		Write-Error 'Start in elevated PowerShell session'
		break
	}

	if ($PSVersionTable.PSEdition -ne 'Core'){
		if (Get-Command -Name 'pwsh.exe' -ErrorAction SilentlyContinue){
			pwsh.exe -Command "Import-Module $PSScriptRoot; Start-WDT"
			break
		}
	}

	$Info = Get-WDTClientInfo

	while ($true){
		Clear-Host

		Write-Host
		Write-Host "  || -- Windows Deployment TUI v0.1.0 -- ||" -ForegroundColor Magenta
		Write-Host
		Write-Host "  Windows $($Info.WinVersion) - $($Info.Architecture) - $($Info.ProductType) - PowerShell $($Info.PSVersion)"
		Write-Host "  System: $($Info.Model)"
		Write-Host
		Write-Host "   - GENERAL -" -ForegroundColor Yellow
		Write-Host "  0. Install WDT requirements"
		Write-Host "  1. Generic settings (taskbar)"
		Write-Host "  2. Install TightVNC server"
		Write-Host "  3. Install programs"
		Write-Host "  9. Uninstall TightVNC server"
		Write-Host
		Write-Host "   - OPTIONAL -" -ForegroundColor Yellow
		Write-Host "  a. Install Chocolatey"
		Write-Host "  b. Remove Appx packages (current user)"
		Write-Host
		Write-Host "  r. Reload in PowerShell Core"
		Write-Host "  q. Quit" -ForegroundColor Red
		Write-Host
		
		$Choice = Read-Host "  Choice"
		Write-Host
		
		switch ($Choice) {
			0 { Install-WDTRequirements -PSVersion $Info.PSVersion }
			1 { Set-WDTGeneralSettings -WinVersion $Info.WinVersion }
			2 {
				if (Find-WDTChocoGet){
					Write-WDTStatus 'Install TightVNC Server'
					Install-Package -Name 'tightvnc' -ProviderName ChocolateyGet -AdditionalArguments '--installarguments "ADDLOCAL=Server VALUE_OF_ACCEPTHTTPCONNECTIONS=0 SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=0 SET_PASSWORD=1 VALUE_OF_PASSWORD="' -Force | Out-Null
					Write-WDTStatus 'Done'
				}
			}
			3 {
				if (Find-WDTChocoGet){
					$Packages = Read-WDTChocoPackages
					Install-WDTChocoPackages -Packages $Packages
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
			b { Remove-WDTAppx }

			r {
				pwsh.exe -Command "Import-Module $PSScriptRoot; Start-WDT"
				return
			}
			q {
				return
			}
			default { Write-Warning "Type a digit or a letter" }
		}
		
		Write-Host
		Read-Host "Press enter to return to menu"
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
		Write-WDTStatus "Install PackageManagement module"
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
	Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
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

	if ($WinVersion -eq "6.1" -or $WinVersion -eq "6.2" -or $WinVersion -eq "6.3" -or $WinVersion -eq "10.0"){
		Write-Host "OS >= Win7: Taakbalkknoppen verbreden" -ForegroundColor green
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 1 -PropertyType 'dword' -Force | Out-Null
	
		Write-Host "OS >= Win7: Notificaties allemaal weergeven" -ForegroundColor green
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | New-ItemProperty -Name "NoAutoTrayNotify" -Value 1 -PropertyType 'dword' | Out-Null
	}

	if ($WinVersion -eq "10.0"){
		Write-Host "OS >= Win10: Search bar verbergen" -ForegroundColor green
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -PropertyType 'dword' -Force | Out-Null

		Write-Host "OS >= Win10: Meet Now verbergen" -ForegroundColor green
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1 -PropertyType 'dword' -Force | Out-Null

		Write-Host "OS >= Win10: OneDrive uitschakelen" -ForegroundColor green
		Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDrive' -ErrorAction SilentlyContinue | Remove-ItemProperty -Name 'OneDrive'
	}
	
	Write-Host "Explorer opnieuw opstarten" -ForegroundColor green
	Stop-Process -Name Explorer
}

function Remove-WDTAppx {
	if ($PSVersionTable.PSEdition -eq 'Core'){
		Import-Module Appx -UseWindowsPowerShell -WarningAction SilentlyContinue
	} else {
		Import-Module Appx
	}

	$Apps = Import-Csv "$PSScriptRoot\data\appx.csv"

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

	foreach ($App in $Remove){
		Write-WDTStatus $App.Name + ' (' + $App.FriendlyName + ')'
		Get-AppxPackage -Name $App.Name | Remove-AppxPackage -Confirm:$false
	}
}