[string] $Operator                         = "Operator"
[String] $Global:DefaultOperatorRight      = $Global:Rights.Deny
$Global:RoleOperator = @()

$PSO = [PSCustomObject]@{
    Name    = [string]$Operator
    Member  = [string]@("ADVALORE\APP_SCHDSVC_ADMIN")
}
$Global:RoleOperator += $PSO 

$Global:Roles += $Global:RoleOperator