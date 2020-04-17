#rename this file to Vars.ps1 
    $ProjectPath = "C:\Projects"
#### Script params
    [string] $Global:ProjectFolder        = "C:\DATA\Projects"
    [string] $Global:PathToAnalyzedFolder = "$Global:ProjectFolder\ErrorLogWatcher"
    [string] $Global:LogFilePath          = "$ProjectPath\LOGS\SetPermissions.log"
    [string] $Global:SetPermissionErrors  = "$ProjectPath\LOGS\SetPermissionErrors.log"
    [array]  $Global:Roles                = @()

    [System.Security.Principal.NTAccount] $Global:Owner = "user1@company.local"

$FileRoles = Get-ChildItem -path "$ProjectPath\ROLES" -File -Filter "role*.ps1"  
foreach ($Role in $FileRoles){
    Get-VarsFromFile  $Role.fullName
}

$Global:Rights = [PSCustomObject]@{
    FC      = "FullControl"
    Read    = "Read"
    Modify  = "Modify"
    Execute = "ExecuteFile"
    Deny    = "Deny"
}

$Global:Modes = [PSCustomObject]@{
    Replace = "Replace"
    Append  = "Append"
}