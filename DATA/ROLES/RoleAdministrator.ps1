[String] $Global:DefaultAdministratorRight = $Global:Rights.FC
$Role = "Administrator"
Get-SettingsFromFile $Global:RoleMembersFile
$Global:Roles += $Global:RoleAdministrator