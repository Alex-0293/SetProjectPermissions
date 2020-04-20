<#
    .SYNOPSIS 
        Alexk
        xx.xx.xxxx
        1
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
#>
$ImportResult = Import-Module AlexkUtils  -PassThru
if ($null -eq $ImportResult) {
    Write-Host "Module 'AlexkUtils' does not loaded!"
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
            $MyScriptRoot = $PWD
        }        
        else {
            Write-Host "Where i am? What is my work dir?"
        }
    }
    else {
        $MyScriptRoot = $PSScriptRoot
    }
    return $MyScriptRoot
}
# Error trap
trap {
    Get-ErrorReporting $_    
    exit 1
}
#########################################################################

Clear-Host

[string]$Global:MyScriptRoot = Get-WorkDir
[string]$Global:GlobalSettingsPath = "C:\DATA\Projects\GlobalSettings\SETTINGS\Settings.ps1"

Get-SettingsFromFile -SettingsFile $Global:GlobalSettingsPath
Get-SettingsFromFile -SettingsFile "$ProjectRoot\$SETTINGSFolder\Settings.ps1"
Initialize-Logging   "$ProjectRoot\$LOGSFolder\$ErrorsLogFileName" "Latest"

foreach ($Folder in $global:FoldersToApplyPath) {
    $Projects = Get-ChildItem -path $Folder -Directory  -ErrorAction SilentlyContinue

    Foreach($Project in $Projects){
        if (!($IgnoreFolders -contains $Project.Name)){
            $ProjectPath = $Project.FullName
            Write-Host $ProjectPath
            [string]$ACLFile = "$ProjectPath\ACL\ACL.xml"
            [string]$RolesFile = "$ProjectPath\ACL\Roles.csv"
            if (!((Test-Path $ACLFile) -and (Test-Path $RolesFile)) -or $Global:RegenerateACL) {
                & $MyScriptRoot\GenerateACL.ps1 $ProjectPath
            }
            & $MyScriptRoot\SetProjectPermissions.ps1 $ProjectPath
        }
    }
}