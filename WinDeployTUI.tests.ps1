Import-Module '.\WinDeployTUI\WinDeployTUI.psm1' -Force
Import-Module '.\WinDeployTUI\WinDeployTUI.psd1' -Force

Start-WDT

Set-WDTGeneralSettings -WinVersion 10.0