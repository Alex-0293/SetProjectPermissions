[string] $Operator                         = "Operator"
[String] $Global:DefaultOperatorRight      = $Global:Rights.Deny
$Global:RoleOperator = @()

$PSO = [PSCustomObject]@{
    Name    = [string]$Operator
    Member = [string]@("AB\APP_SCHEDULER")
}
$Global:RoleOperator += $PSO 

$Global:Roles += $Global:RoleOperator