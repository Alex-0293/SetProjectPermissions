[string] $Administrator = "Administrator"
[String] $Global:DefaultAdministratorRight = $Global:Rights.FC
[array]  $Global:RoleAdministrator = @() 

$PSO = [PSCustomObject]@{
    Name    = [string]$Administrator
    Member  = [string]"AB\User1"
} 

$Global:RoleAdministrator += $PSO

$PSO = [PSCustomObject]@{
    Name   = [string]$Administrator
    Member = [string]"AB-113\User"
} 

$Global:RoleAdministrator += $PSO

$PSO = [PSCustomObject]@{
    Name   = [string]$Administrator
    Member = [string]"AB\Admin1"
} 

$Global:RoleAdministrator += $PSO

$Global:Roles += $Global:RoleAdministrator