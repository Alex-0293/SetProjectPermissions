[String] $Global:DefaultAdministratorRight = $Global:Rights.FC
$Role = "Administrator"
Get-VarsFromFile $Global:RoleMembersFile
$Global:Roles += $Global:RoleAdministrator