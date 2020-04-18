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

$ImportResult = Import-Module AlexkUtils  -PassThru -force
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
[string]$MyScriptRoot        = Get-WorkDir
[string]$Global:ProjectRoot  = Split-Path $MyScriptRoot -parent

Get-VarsFromFile    "$ProjectRoot\VARS\Vars.ps1"
Initialize-Logging   $ProjectRoot "Latest"

if (!$ScriptRoot) {
    $ScriptRoot = $Global:PathToAnalyzedFolder
    Clear-Host
}

If ($Global:RegenerateACL) {
    Add-ToLog -Message "Generate ACL to project [$ScriptRoot]" -logFilePath $Global:LogFilePath -display -status "Info"

    [array]  $Objects       = @()
    [array]  $ExportObjects = @()
    [string] $ProjectName   = Split-Path -Path $ScriptRoot -Leaf

    ############# RoleAdministrator ################
    $RootFolder = [PSCustomObject]@{
        Role  = $Global:RoleAdministrator[0].Name
        Path  = "$ScriptRoot"
        Right = @($Global:Rights.FC) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $RootFolder

    $KEYSFolder = [PSCustomObject]@{
        Role  = $Global:RoleAdministrator[0].Name
        Path  = "$ScriptRoot\KEYS"
        Right = @($Global:Rights.FC) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $KEYSFolder

    $LOGSFolder = [PSCustomObject]@{
        Role  = $Global:RoleAdministrator[0].Name
        Path  = "$ScriptRoot\LOGS"
        Right = @($Global:Rights.FC) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $LOGSFolder

    $SETTINGSFolder = [PSCustomObject]@{
        Role  = $Global:RoleAdministrator[0].Name
        Path  = "$ScriptRoot\SETTINGS"
        Right = @($Global:Rights.FC) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $SETTINGSFolder

    $ACLFolder = [PSCustomObject]@{
        Role  = $Global:RoleAdministrator[0].Name
        Path  = "$ScriptRoot\ACL"
        Right = @($Global:Rights.FC) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $ACLFolder

    $DATAFolder = [PSCustomObject]@{
        Role  = $Global:RoleAdministrator[0].Name
        Path  = "$ScriptRoot\DATA"
        Right = @($Global:Rights.FC) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $DATAFolder

    $SCRIPTSFolder = [PSCustomObject]@{
        Role  = $Global:RoleAdministrator[0].Name
        Path  = "$ScriptRoot\SCRIPTS"
        Right = @($Global:Rights.FC) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $SCRIPTSFolder

    $VARSFolder = [PSCustomObject]@{
        Role  = $Global:RoleAdministrator[0].Name
        Path  = "$ScriptRoot\VARS"
        Right = @($Global:Rights.FC) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $VARSFolder
    ############# RoleOperator ################
    $RootFolder = [PSCustomObject]@{
        Role  = $Global:RoleOperator[0].Name
        Path  = "$ScriptRoot"
        Right = @($Global:Rights.Modify, $Global:Rights.Execute)  -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $RootFolder

    $KEYSFolder = [PSCustomObject]@{
        Role  = $Global:RoleOperator[0].Name
        Path  = "$ScriptRoot\KEYS"
        Right = @($Global:Rights.Read) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $KEYSFolder

    $LOGSFolder = [PSCustomObject]@{
        Role  = $Global:RoleOperator[0].Name
        Path  = "$ScriptRoot\LOGS"
        Right = @($Global:Rights.Read, $Global:Rights.Modify) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $LOGSFolder

    $SETTINGSFolder = [PSCustomObject]@{
        Role  = $Global:RoleOperator[0].Name
        Path  = "$ScriptRoot\SETTINGS"
        Right = @($Global:Rights.Read) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $SETTINGSFolder

    $ACLFolder = [PSCustomObject]@{
        Role  = $Global:RoleOperator[0].Name
        Path  = "$ScriptRoot\ACL"
        Right = @($Global:Rights.Deny) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $ACLFolder

    $DATAFolder = [PSCustomObject]@{
        Role  = $Global:RoleOperator[0].Name
        Path  = "$ScriptRoot\DATA"
        Right = @($Global:Rights.Modify) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $DATAFolder

    $SCRIPTSFolder = [PSCustomObject]@{
        Role  = $Global:RoleOperator[0].Name
        Path  = "$ScriptRoot\SCRIPTS"
        Right = @($Global:Rights.Read, $Global:Rights.Execute) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $SCRIPTSFolder

    $VARSFolder = [PSCustomObject]@{
        Role  = $Global:RoleOperator[0].Name
        Path  = "$ScriptRoot\VARS"
        Right = @($Global:Rights.Read, $Global:Rights.Execute) -join ", "
        Mode  = $Global:Modes.Replace
    }
    $Objects += $VARSFolder

    Foreach ($item in $objects){
        If(test-path $Item.path){
            $ExportObjects += $Item
        }
    }


    $Objects = Get-ChildItem -path $ScriptRoot -ErrorAction SilentlyContinue
    ForEach($Object in $Objects){
        if (!($ExportObjects.path -contains $Object.FullName)) {
            $NewObject = [PSCustomObject]@{
                Role  = $Global:RoleOperator[0].Name
                Path  = $Object.FullName
                Right = @($Global:DefaultOperatorRight)  -join ", "
                Mode  = $Global:Modes.Replace
            }
            $ExportObjects += $NewObject

            $NewObject = [PSCustomObject]@{
                Role  = $Global:RoleAdministrator[0].Name
                Path  = $Object.FullName
                Right = @($Global:DefaultAdministratorRight)  -join ", "
                Mode  = $Global:Modes.Replace
            }
            $ExportObjects += $NewObject
        }
    }
 
    $ExportObjects | Sort-Object path | Format-Table -AutoSize
    #$Roles         | Format-Table -AutoSize

    if (Test-Path "$ScriptRoot\ACL"){
        Remove-Item -path "$ScriptRoot\ACL" -force -recurse  | Out-Null
    }
    New-Item -path "$ScriptRoot\ACL" -ItemType Directory | Out-Null
    
    $Owner = [PSCustomObject]@{
        Owner = $Global:Owner
    }

    $ExportObjects | Export-Csv "$ScriptRoot\ACL\ACL.csv" -Encoding utf8 -Force   
    $Roles | Export-Csv "$ScriptRoot\ACL\Roles.csv" -Encoding utf8 -Force    
    $Owner | Export-Csv "$ScriptRoot\ACL\Owner.csv" -Encoding utf8 -Force 

    Add-ToLog -Message "ACL Generated!" -logFilePath $Global:LogFilePath -display -status "Info"
}
Else {
    Add-ToLog -Message "ACL Generation disabled." -logFilePath $Global:LogFilePath -display -status "Warning"
}