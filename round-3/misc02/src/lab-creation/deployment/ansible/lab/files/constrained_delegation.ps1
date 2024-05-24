Set-ADUser -Identity "TimeSheetSvc" -ServicePrincipalNames @{Add='HTTP/timesheet.factories.mammamia.local'}
Get-ADUser -Identity "TimeSheetSvc" | Set-ADAccountControl -TrustedToAuthForDelegation $true
Set-ADUser -Identity "TimeSheetSvc" -Add @{'msDS-AllowedToDelegateTo'=@('CIFS/mgmtdc.factories.mammamia.local','CIFS/mgmtdc')}