<#
    .SYNOPSIS 
        .AUTOR
        DATE
        VER
    .DESCRIPTION
    
    .EXAMPLE
#>
Param (
    [Parameter( Mandatory = $false, Position = 0, HelpMessage = "Initialize global settings." )]
    [bool] $InitGlobal = $true,
    [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Initialize local settings." )]
    [bool] $InitLocal = $true   
)
$Global:ScriptInvocation = $MyInvocation
if ($env:AlexKFrameworkInitScript){. "$env:AlexKFrameworkInitScript" -MyScriptRoot (Split-Path $PSCommandPath -Parent) -InitGlobal $InitGlobal -InitLocal $InitLocal} Else {Write-host "Environmental variable [AlexKFrameworkInitScript] does not exist!" -ForegroundColor Red; exit 1}

# Error trap
trap {
    if (get-module -FullyQualifiedName AlexkUtils) {
       Get-ErrorReporting $_

        . "$($Global:gsGlobalSettingsPath)\$($Global:gsSCRIPTSFolder)\Finish.ps1"  
    }
    Else {
        Write-Host "[$($MyInvocation.MyCommand.path)] There is error before logging initialized. Error: $_" -ForegroundColor Red
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
            [string]$ACLFilePath   = "$ProjectPath\$($Global:gsACLFolder)\$AccessFileName"
            [string]$RolesFilePath = "$ProjectPath\$($Global:gsACLFolder)\$RolesFileName"
            [string]$OwnerFilePath = "$ProjectPath\$($Global:gsACLFolder)\$OwnerFileName"
            $ACLFilesExist = ((Test-Path $ACLFilePath) -and (Test-Path $RolesFilePath) -and (Test-Path $OwnerFilePath))
            #$ACLFilesExist
            if (!$ACLFilesExist -or $Global:RegenerateACL) {
                & $MyScriptRoot\GenerateACL.ps1 $ProjectPath  -InitGlobal $false -InitLocal $false
            }
            & $MyScriptRoot\SetProjectPermissions.ps1 $ProjectPath -InitGlobal $false -InitLocal $false
        }
    }
}

################################# Script end here ###################################
. "$($Global:gsGlobalSettingsPath)\$($Global:gsSCRIPTSFolder)\Finish.ps1"
