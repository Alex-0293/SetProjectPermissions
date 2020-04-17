[string] $Administrator = "Administrator"
[String] $Global:DefaultAdministratorRight = $Global:Rights.FC
[array]  $Global:RoleAdministrator = @() 

$PSO = [PSCustomObject]@{
    Name    = [string]$Administrator
    Member  = [string]"Advalore\Admin1"
} 

$Global:RoleAdministrator += $PSO

$Global:Roles += $Global:RoleAdministrator