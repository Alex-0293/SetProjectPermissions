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
    [bool] $InitLocal  = $true,
    [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Set script root." )]
    [string] $PathToFolder   
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

if (!$PathToFolder) {
    $PathToFolder = $Global:PathToAnalyzedFolder
}
Add-ToLog -Message "Generating ACL for folder [$PathToFolder]." -logFilePath $Global:gsScriptLogFilePath -display -status "info"
if (Test-Path $PathToFolder){
    If ($Global:RegenerateACL -or !(Test-Path "$PathToFolder\$ACLFolder")) {
        [array]  $Objects            = @()
        [array]  $ExportObjects      = @()
        [array]  $SPECIALFoldersCopy = @()

        ############# RoleAdministrator ################
        $SPECIALFoldersCopy = $Global:gsSPECIALFolders
        $SPECIALFoldersCopy += ""

        foreach ($Folder in $SPECIALFoldersCopy) {
            $ObjFolder = [PSCustomObject]@{
                Role  = $Global:RoleAdministrator[0].Name
                Path  = "$PathToFolder\$Folder"
                Right = @($Global:Rights.FC) -join ", "
                Mode  = $Global:Modes.Replace
            }
            $Objects += $ObjFolder
        }

        ############# RoleOperator ################
        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$PathToFolder\"
            Right = @($Global:Rights.Modify)  -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder  

        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$PathToFolder\$DATAFolder"
            Right = @($Global:Rights.Modify) -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder

        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$PathToFolder\$ACLFolder"
            Right = @($Global:Rights.Deny) -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder   
        
        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$PathToFolder\$LOGSFolder"
            Right = @($Global:Rights.Read, $Global:Rights.Write) -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder  

        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$PathToFolder\$SCRIPTSFolder"
            Right = @($Global:Rights.Read, $Global:Rights.Execute) -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder  
        
        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$PathToFolder\$SETTINGSFolder"
            Right = @($Global:Rights.Read, $Global:Rights.Execute) -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder   
        
        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$PathToFolder\$VALUESFolder"
            Right = @($Global:Rights.Read) -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder 

        if (Test-Path "$PathToFolder\$ACLFolder") {
            Remove-Item -path "$PathToFolder\$ACLFolder" -force -recurse | Out-Null
        }
        New-Item -path "$PathToFolder\$ACLFolder" -ItemType Directory -Force | Out-Null
        
        Foreach ($item in $Objects){
            If(test-path $Item.path){
                $ExportObjects += $Item
            }
        }

        $Objects = Get-ChildItem -path $PathToFolder -ErrorAction SilentlyContinue
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
    
        #$ExportObjects | Sort-Object path | Format-Table -AutoSize
        #$Roles         | Format-Table -AutoSize   
        
        $Owner = [PSCustomObject]@{
            Owner = $Global:Owner
        }

        $ExportObjects |Sort-Object path | Export-Csv "$PathToFolder\$($Global:gsACLFolder)\$AccessFileName" -Encoding utf8 -Force   
        $Roles | Export-Csv "$PathToFolder\$($Global:gsACLFolder)\$RolesFileName" -Encoding utf8 -Force    
        $Owner | Export-Csv "$PathToFolder\$($Global:gsACLFolder)\$OwnerFileName" -Encoding utf8 -Force 

    }
    Else {
        Add-ToLog -Message "ACL Generation disabled." -logFilePath $Global:gsScriptLogFilePath -display -status "Warning"
    }
}
Else {
        Add-ToLog -Message "Path [$PathToFolder] not found." -logFilePath $Global:gsScriptLogFilePath -display -status "Warning"
}    

################################# Script end here ###################################
. "$($Global:gsGlobalSettingsPath)\$($Global:gsSCRIPTSFolder)\Finish.ps1"
