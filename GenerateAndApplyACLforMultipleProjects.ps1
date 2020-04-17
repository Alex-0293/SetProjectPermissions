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

$MyScriptRoot = Get-WorkDir

Get-VarsFromFile    "$MyScriptRoot\Vars.ps1"
Initialize-Logging   $MyScriptRoot "Latest"

[array]$IgnoreFolders = @(".vscode")

$Projects = Get-ChildItem -path $Global:ProjectFolder -Directory

Foreach($Project in $Projects){
    if (!($IgnoreFolders -contains $Project.Name)){
        Write-Host $Project.FullName
        & $MyScriptRoot\GenerateACL.ps1 $Project.FullName
        & $MyScriptRoot\SetProjectPermissions.ps1 $Project.FullName
    }
}