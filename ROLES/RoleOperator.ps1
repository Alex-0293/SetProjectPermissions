[String] $Global:DefaultOperatorRight      = $Global:Rights.Deny
$Role = "Operator"
Get-VarsFromFile $Global:RoleMembersFile
$Global:Roles += $Global:RoleOperator