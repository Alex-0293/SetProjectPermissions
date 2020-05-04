<#
    .SYNOPSIS 
        .AUTOR
        .DATE
        .VER
    .DESCRIPTION
    .PARAMETER
    .EXAMPLE
#>
$MyScriptRoot = "C:\DATA\ProjectServices\SetProjectPermissions\SCRIPTS"
$InitScript = "C:\DATA\Projects\GlobalSettings\SCRIPTS\Init.ps1"

. "$InitScript" -MyScriptRoot $MyScriptRoot

# Error trap
trap {
    if ($Global:Logger) {
        Get-ErrorReporting $_ 
    }
    Else {
        Write-Host "There is error before logging initialized." -ForegroundColor Red
    }   
    exit 1
}
################################# Script start here #################################

if (!$ScriptRoot) {
    $ScriptRoot = $Global:PathToAnalyzedFolder
    Clear-Host
}
if (Test-Path $ScriptRoot){
    If ($Global:RegenerateACL -or !(Test-Path "$ScriptRoot\$ACLFolder")) {
        Add-ToLog -Message "Generate ACL to project [$ScriptRoot]" -logFilePath $Global:ScriptLogFilePath -display -status "Info"

        [array]  $Objects            = @()
        [array]  $ExportObjects      = @()
        [array]  $SPECIALFoldersCopy = @()

        ############# RoleAdministrator ################
        $SPECIALFoldersCopy = $Global:SPECIALFolders
        $SPECIALFoldersCopy += ""

        foreach ($Folder in $SPECIALFoldersCopy) {
            $ObjFolder = [PSCustomObject]@{
                Role  = $Global:RoleAdministrator[0].Name
                Path  = "$ScriptRoot\$Folder"
                Right = @($Global:Rights.FC) -join ", "
                Mode  = $Global:Modes.Replace
            }
            $Objects += $ObjFolder
        }

        ############# RoleOperator ################
        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$ScriptRoot\"
            Right = @($Global:Rights.Modify)  -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder  

        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$ScriptRoot\$DATAFolder"
            Right = @($Global:Rights.Modify) -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder

        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$ScriptRoot\$ACLFolder"
            Right = @($Global:Rights.Deny) -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder   
        
        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$ScriptRoot\$LOGSFolder"
            Right = @($Global:Rights.Read, $Global:Rights.Write) -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder  

        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$ScriptRoot\$SCRIPTSFolder"
            Right = @($Global:Rights.Read, $Global:Rights.Execute) -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder  
        
        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$ScriptRoot\$SETTINGSFolder"
            Right = @($Global:Rights.Read, $Global:Rights.Execute) -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder   
        
        $ObjFolder = [PSCustomObject]@{
            Role  = $Global:RoleOperator[0].Name
            Path  = "$ScriptRoot\$VALUESFolder"
            Right = @($Global:Rights.Read) -join ", "
            Mode  = $Global:Modes.Replace
        }
        $Objects += $ObjFolder 

        if (Test-Path "$ScriptRoot\$ACLFolder") {
            Remove-Item -path "$ScriptRoot\$ACLFolder" -force -recurse | Out-Null
        }
        New-Item -path "$ScriptRoot\$ACLFolder" -ItemType Directory | Out-Null
        
        Foreach ($item in $Objects){
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
        
        $Owner = [PSCustomObject]@{
            Owner = $Global:Owner
        }

        $ExportObjects |Sort-Object path | Export-Csv "$ScriptRoot\$ACLFolder\$AccessFileName" -Encoding utf8 -Force   
        $Roles | Export-Csv "$ScriptRoot\$ACLFolder\$RolesFileName" -Encoding utf8 -Force    
        $Owner | Export-Csv "$ScriptRoot\$ACLFolder\$OwnerFileName" -Encoding utf8 -Force 

        Add-ToLog -Message "ACL Generated!" -logFilePath $Global:ScriptLogFilePath -display -status "Info"
    }
    Else {
        Add-ToLog -Message "ACL Generation disabled." -logFilePath $Global:ScriptLogFilePath -display -status "Warning"
    }
}
Else {
        Add-ToLog -Message "Path [$ScriptRoot] not found." -logFilePath $Global:ScriptLogFilePath -display -status "Warning"
}    

################################# Script end here ###################################
. "$GlobalSettings\$SCRIPTSFolder\Finish.ps1"