<#
    .SYNOPSIS 
        .AUTOR
        .DATE
        .VER
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
#>
Clear-Host
$Global:ScriptName = $MyInvocation.MyCommand.Name
$InitScript = "C:\DATA\Projects\GlobalSettings\SCRIPTS\Init.ps1"
if (. "$InitScript" -MyScriptRoot (Split-Path $PSCommandPath -Parent) -force) { exit 1 }

# Error trap
trap {
    if ($Global:Logger) {
       Get-ErrorReporting $_
        . "$GlobalSettings\$SCRIPTSFolder\Finish.ps1"  
    }
    Else {
        Write-Host "There is error before logging initialized." -ForegroundColor Red
    }   
    exit 1
}
################################# Script start here #################################

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
            #$ACLFilesExist
            if (!$ACLFilesExist -or $Global:RegenerateACL) {
                & $MyScriptRoot\GenerateACL.ps1 $ProjectPath
            }
            & $MyScriptRoot\SetProjectPermissions.ps1 $ProjectPath
        }
    }
}

################################# Script end here ###################################
. "$GlobalSettings\$SCRIPTSFolder\Finish.ps1"