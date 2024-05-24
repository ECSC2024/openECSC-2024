# https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon
if(-not(query session silvia.galli /server:factws)) {
  #kill process if exist
  try {
    Get-Process mstsc -IncludeUserName | Where {$_.UserName -eq "factories\silvia.galli"}|Stop-Process -Force
  } catch {
    Write-Host "No process to kill"
  }
  #run the command
  mstsc /v:factws /remoteGuard
}