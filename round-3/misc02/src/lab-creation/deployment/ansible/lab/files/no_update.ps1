# set the Windows Update service to "disabled"
sc.exe config wuauserv start=disabled

$ServiceName = 'wuauserv'
$arrService = Get-Service -Name $ServiceName
if ($arrService.Status -ne 'Stopped')
{
	Stop-Service $ServiceName
}

New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows' -Name 'WindowsUpdate' -Force
New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name 'AU' -Force
New-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -name 'NoAutoUpdate' -value '1' -propertyType "DWord" -force