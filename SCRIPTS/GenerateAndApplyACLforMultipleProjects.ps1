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
Function Initialize-Script   () {
    [string]$Global:MyScriptRoot = Get-WorkDir
    [string]$Global:GlobalSettingsPath = "C:\DATA\Projects\GlobalSettings\SETTINGS\Settings.ps1"

    Get-SettingsFromFile -SettingsFile $Global:GlobalSettingsPath
    if ($GlobalSettingsSuccessfullyLoaded) {    
        Get-SettingsFromFile -SettingsFile "$ProjectRoot\$($Global:SETTINGSFolder)\Settings.ps1"
        if ($Global:LocalSettingsSuccessfullyLoaded) {
            Initialize-Logging   "$ProjectRoot\$LOGSFolder\$ErrorsLogFileName" "Latest"
            Write-Host "Logging initialized."            
        }
        Else {
            Add-ToLog -Message "[Error] Error loading local settings!" -logFilePath "$(Split-Path -path $Global:MyScriptRoot -parent)\$LOGSFolder\$ErrorsLogFileName" -Display -Status "Error" -Format 'yyyy-MM-dd HH:mm:ss'
            Exit 1 
        }
    }
    Else { 
        Add-ToLog -Message "[Error] Error loading global settings!" -logFilePath "$(Split-Path -path $Global:MyScriptRoot -parent)\LOGS\Errors.log" -Display -Status "Error" -Format 'yyyy-MM-dd HH:mm:ss'
        Exit 1
    }
}
# Error trap
trap {
    Get-ErrorReporting $_    
    exit 1
}
#########################################################################

Clear-Host
Initialize-Script

foreach ($Folder in $global:FoldersToApplyPath) {
    $Projects = Get-ChildItem -path $Folder -Directory  -ErrorAction SilentlyContinue
    Foreach($Project in $Projects){
        if (!($FoldersToIgnoreName -contains $Project.Name)) {
            $ProjectPath = $Project.FullName
            Write-Host $ProjectPath
            [string]$ACLFilePath   = "$ProjectPath\$ACLFolder\$AccessFileName"
            [string]$RolesFilePath = "$ProjectPath\$ACLFolder\$RolesFileName"
            [string]$OwnerFilePath = "$ProjectPath\$ACLFolder\$OwnerFileName"
            $ACLFilesExist = ((Test-Path $ACLFilePath) -and (Test-Path $RolesFilePath) -and (Test-Path $OwnerFilePath))
            $ACLFilesExist
            if (!$ACLFilesExist -or $Global:RegenerateACL) {
                & $MyScriptRoot\GenerateACL.ps1 $ProjectPath
            }
            & $MyScriptRoot\SetProjectPermissions.ps1 $ProjectPath
        }
    }
}