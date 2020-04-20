[String] $Global:DefaultOperatorRight      = $Global:Rights.Deny
$Role = "Operator"
Get-SettingsFromFile $Global:RoleMembersFile
$Global:Roles += $Global:RoleOperator