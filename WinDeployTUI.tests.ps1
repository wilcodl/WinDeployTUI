Import-Module '.\WinDeployTUI.psm1' -Force
Import-Module '.\WinDeployTUI.psd1' -Force

Start-WDT

Set-WDTGeneralSettings -WinVersion 10.0