<#
    .SYNOPSIS 
        Alexk
        xx.xx.xxxx
        1
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
#>
Param (
    [string] $ScriptRoot
)

$ImportResult = Import-Module AlexkUtils  -PassThru
if ($null -eq $ImportResult) {
    Modify-Host "Module 'AlexkUtils' does not loaded!"
    exit 1
}
else {
    $ImportResult = $null
}
#requires -version 3

#########################################################################
function Get-WorkDir () {
    if ($PSScriptRoot -eq "") {
        if ($PWD -ne "") {
            $ScriptRoot = $PWD
        }        
        else {
            Modify-Host "Where i am? What is my work dir?"
        }
    }
    else {
        $ScriptRoot = $PSScriptRoot
    }
    return $ScriptRoot
}
# Error trap
trap {
    Get-ErrorReporting $_    
    exit 1
}
#########################################################################

if (!$ScriptRoot){
    $ScriptRoot   = $Global:PathToAnalyzedFolder
    Clear-Host
}

$MyScriptRoot = Get-WorkDir

Get-VarsFromFile    "$MyScriptRoot\Vars.ps1"
Initialize-Logging   $MyScriptRoot "Latest"

Add-ToLog -Message "Generate ACL to project [$ScriptRoot]" -logFilePath $Global:LogFilePath -display -status "Info"

[array]  $Objects       = @()
[array]  $ExportObjects = @()
[string] $ProjectName   = Split-Path -Path $ScriptRoot -Leaf

############# Role1 ################
$RootFolder = [PSCustomObject]@{
    Role  = $Global:RoleAdministrator.Name
    Path  = "$ScriptRoot"
    Right = @($Global:Rights.FC)
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $RootFolder

$KEYSFolder = [PSCustomObject]@{
    Role  = $Global:RoleAdministrator.Name
    Path  = "$ScriptRoot\KEYS"
    Right = @($Global:Rights.FC)
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $KEYSFolder

$LOGSFolder = [PSCustomObject]@{
    Role  = $Global:RoleAdministrator.Name
    Path  = "$ScriptRoot\LOGS"
    Right = @($Global:Rights.FC)
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $LOGSFolder

$SETTINGSFolder = [PSCustomObject]@{
    Role  = $Global:RoleAdministrator.Name
    Path  = "$ScriptRoot\SETTINGS"
    Right = @($Global:Rights.FC)
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $SETTINGSFolder

$ACLFolder = [PSCustomObject]@{
    Role  = $Global:RoleAdministrator.Name
    Path  = "$ScriptRoot\ACL"
    Right = @($Global:Rights.FC)
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $ACLFolder

$FileName = "$ProjectName.ps1"
$File = [PSCustomObject]@{
    Role  = $Global:RoleAdministrator.Name
    Path  = "$ScriptRoot\$FileName"
    Right = @($Global:Rights.FC) 
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $File

$FileName = "$ProjectName.xml"
$File = [PSCustomObject]@{
    Role  = $Global:RoleAdministrator.Name
    Path  = "$ScriptRoot\$FileName"
    Right = @($Global:Rights.FC) 
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $File

$FileName = "Vars.ps1"
$File = [PSCustomObject]@{
    Role  = $Global:RoleAdministrator.Name
    Path  = "$ScriptRoot\$FileName"
    Right = @($Global:Rights.FC) 
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner 
}
$Objects += $File

$FileName = ".gitignore"
$File = [PSCustomObject]@{
    Role  = $Global:RoleAdministrator.Name
    Path  = "$ScriptRoot\$FileName"
    Right = @($Global:Rights.FC) 
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $File

$FileName = "Vars-empty.ps1"
$File = [PSCustomObject]@{
    Role  = $Global:RoleAdministrator.Name
    Path  = "$ScriptRoot\$FileName"
    Right = @($Global:Rights.FC) 
    Mode  = $Global:Modes.Replace 
    Owner = $Global:Owner
}
$Objects += $File

############# Role2 ################
$RootFolder = [PSCustomObject]@{
    Role  = $Global:RoleOperator.Name
    Path  = "$ScriptRoot"
    Right = @($Global:Rights.Modify, $Global:Rights.Execute) 
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $RootFolder

$KEYSFolder = [PSCustomObject]@{
    Role  = $Global:RoleOperator.Name
    Path  = "$ScriptRoot\KEYS"
    Right = @($Global:Rights.Read)
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $KEYSFolder

$LOGSFolder = [PSCustomObject]@{
    Role  = $Global:RoleOperator.Name
    Path  = "$ScriptRoot\LOGS"
    Right = @($Global:Rights.Read, $Global:Rights.Modify)
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $LOGSFolder

$SETTINGSFolder = [PSCustomObject]@{
    Role  = $Global:RoleOperator.Name
    Path  = "$ScriptRoot\SETTINGS"
    Right = @($Global:Rights.Read)
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $SETTINGSFolder

$ACLFolder = [PSCustomObject]@{
    Role  = $Global:RoleOperator.Name
    Path  = "$ScriptRoot\ACL"
    Right = @($Global:Rights.Deny)
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $ACLFolder

$FileName = "$ProjectName.ps1"
$File = [PSCustomObject]@{
    Role  = $Global:RoleOperator.Name
    Path  = "$ScriptRoot\$FileName"
    Right = @($Global:Rights.Read, $Global:Rights.Execute) 
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $File

$FileName = "$ProjectName.xml"
$File = [PSCustomObject]@{
    Role  = $Global:RoleOperator.Name
    Path  = "$ScriptRoot\$FileName"
    Right = @($Global:Rights.Deny) 
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $File

$FileName = "Vars.ps1"
$File = [PSCustomObject]@{
    Role  = $Global:RoleOperator.Name
    Path  = "$ScriptRoot\$FileName"
    Right = @($Global:Rights.Read, $Global:Rights.Execute)
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner 
}
$Objects += $File

$FileName = ".gitignore"
$File = [PSCustomObject]@{
    Role  = $Global:RoleOperator.Name
    Path  = "$ScriptRoot\$FileName"
    Right = @($Global:Rights.Deny)
    Mode  = $Global:Modes.Replace
    Owner = $Global:Owner
}
$Objects += $File

$FileName = "Vars-empty.ps1"
$File = [PSCustomObject]@{
    Role  = $Global:RoleOperator.Name
    Path  = "$ScriptRoot\$FileName"
    Right = @($Global:Rights.Deny)
    Mode  = $Global:Modes.Replace 
    Owner = $Global:Owner
}
$Objects += $File

Foreach ($item in $objects){
    If(test-path $Item.path){
        $ExportObjects += $Item
    }
}

$Folders = Get-ChildItem -path $ScriptRoot -Directory  -ErrorAction SilentlyContinue
ForEach($Folder in $Folders){
    if (!($ExportObjects.path -contains $Folder.FullName)){
        $NewFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator.Name
            Path  = $Folder.FullName
            Right = @($Global:DefaultOperatorRight)
            Mode  = $Global:Modes.Replace
            Owner = $Global:Owner
        }
        $ExportObjects += $NewFolder

        $NewFolder = [PSCustomObject]@{
            Role  = $Global:RoleAdministrator.Name
            Path  = $Folder.FullName
            Right = @($Global:DefaultAdministratorRight)
            Mode  = $Global:Modes.Replace
            Owner = $Global:Owner
        }
        $ExportObjects += $NewFolder
    }
}

#$ExportObjects | Sort-Object path | Format-Table -AutoSize
#$Roles         | Format-Table -AutoSize

if (Test-Path "$ScriptRoot\ACL"){
    Remove-Item -path "$ScriptRoot\ACL" -force -recurse  | Out-Null
}
New-Item -path "$ScriptRoot\ACL" -ItemType Directory | Out-Null

$ExportObjects | Export-Clixml "$ScriptRoot\ACL\acl.xml" -Encoding utf8 -Force   
$Roles | Export-Csv "$ScriptRoot\ACL\Roles.csv" -Encoding utf8 -Force 

Add-ToLog -Message "ACL Generated!" -logFilePath $Global:LogFilePath -display -status "Info"