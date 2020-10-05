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
    [bool] $InitLocal = $true,
    [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Set script root." )]
    [string] $PathToFolder      
)

$Global:ScriptInvocation = $MyInvocation
if ($env:AlexKFrameworkInitScript){. "$env:AlexKFrameworkInitScript" -MyScriptRoot (Split-Path $PSCommandPath -Parent) -InitGlobal $InitGlobal -InitLocal $InitLocal} Else {Write-host "Environmental variable [AlexKFrameworkInitScript] does not exist!" -ForegroundColor Red; exit 1}
if ($LastExitCode) { exit 1 }
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

Function Set-NTFSAccess ($Path, $Acl) {
    if (Test-Path $Path) {
        $Object = Get-Item -Path $Path              
        foreach ($Role in $Global:LocalRoles) {
            if ($Role.name -eq $Acl.role){   
                $Permissions = @()
                if ($Acl.Right -ne $Global:Rights.deny) {
                    $RuleType            = "Allow"
                    $Rights              = $Acl.Right
                }
                Else {
                    $RuleType            = "Deny"
                    $Rights              = $Global:Rights.FC
                }
                
                if ($Object.PSIsContainer) {
                    $InheritSettings     = "ContainerInherit, ObjectInherit"  
                }
                Else{
                    $InheritSettings     = "None" 
                }
                
                $user                = $Role.Member                    
                $PropagationSettings = "None"
                [array]$Permissions         = $user, $Rights, $InheritSettings, $PropagationSettings, $RuleType
                if ($Permissions) {                    
                    # write-host $Permissions
                    # foreach ($item in $Permissions){
                    #     Write-Host $item  
                    # }
                    $AccessRule          = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permissions                    
                    $PSO = [PSCustomObject]@{
                        Path   = $Path
                        Folder = $Object.PSIsContainer
                        ACL    = $AccessRule
                        Owner  = $Global:Owner
                        Mode   = $Acl.Mode
                    } 
                    $Global:ACLArray += $PSO
                } 
                Else {
                    Add-ToLog -Message "Empty permissions [$Permissions]!" -logFilePath $Global:gsScriptLogFilePath -Display -Status "Error" 
                }
            }            
        }
    }
}

if (!$PathToFolder) {
    $PathToFolder = $Global:PathToAnalyzedFolder
}

[string]$ACLFile   = "$PathToFolder\$($Global:gsACLFolder)\Access.csv"
[string]$RolesFile = "$PathToFolder\$($Global:gsACLFolder)\Roles.csv"
[string]$OwnerFile = "$PathToFolder\$($Global:gsACLFolder)\Owner.csv"

if ((Test-Path $ACLFile) -and (Test-Path $RolesFile) -and (Test-Path $OwnerFile)) {
    
    Add-ToLog -Message "Setting NTFS permissions to project [$PathToFolder]." -logFilePath $Global:gsScriptLogFilePath -display -status "Info" -level ($Global:gsParentLevel + 1)
    [array] $Global:LocalRoles  = @()

    $Global:LocalRoles = Import-Csv -path $RolesFile -Encoding utf8
    $ACL               = Import-Csv -path $ACLFile -Encoding utf8
    $Global:Owner      = (Import-Csv -path $OwnerFile -Encoding utf8)[0].Owner

    [array] $Global:ACLArray = @()
    foreach ($item in $ACL){
        Set-NTFSAccess $item.Path $item  
    }

    $DistinctFolderPath = $Global:ACLArray | Where-Object { $_.Folder -eq $true } | Select-Object Path -Unique
    Foreach ($Item in $DistinctFolderPath) {
        $ItemPath = $Item.path
        Add-ToLog -Message "Processing object [$ItemPath]." -logFilePath $Global:gsScriptLogFilePath -display -status "Info" -level ($Global:gsParentLevel + 1)
        $CurrentACL = Get-Acl $ItemPath

        [void]$CurrentACL.SetAccessRuleProtection($true, $false) # Delete inheritance  

        $ACLs = $Global:ACLArray | Where-Object { $_.path -eq $ItemPath }
        [array]$Rights = @()
        Foreach ($Acl in $ACLs) {  
            if ($Acl.mode -eq $Global:Modes.replace) {  
                $ACLToRemove = $CurrentACL.Access | Where-Object { ($_.IsInherited -eq $false) -and ($_.IdentityReference -eq $Acl.Acl[0].IdentityReference) }       
                foreach ($Item1 in  $ACLToRemove) {
                    [void]$CurrentACL.RemoveAccessRule($Item1) 
                } 
            }            
            
            $Rights += $Acl.ACL          
            
            if ($Acl.mode -eq $Global:Modes.replace) {
                $CurrentACL.SetAccessRule($Acl.ACL) 
            }
            Else {
                $CurrentACL.AddAccessRule($Acl.ACL)  
            }

            $Owner = $Global:Owner
        }
    
        $FileACL = Get-Acl $ItemPath
        
        $RulesIsEqual = $False

        If ($FileACL.Access.count -eq $CurrentACL.Access.count) {
            $RulesIsEqual = $true        
            [array]$AccessArray1 = @()
            foreach ($Rule in $FileACL.Access) {
                $PSO = [PSCustomObject]@{
                    FileSystemRights  = $Rule.FileSystemRights
                    AccessControlType = $Rule.AccessControlType
                    IdentityReference = $Rule.IdentityReference
                    IsInherited       = $Rule.IsInherited
                    InheritanceFlags  = $Rule.InheritanceFlags
                    PropagationFlags  = $Rule.PropagationFlags
                }
                $AccessArray1 += $PSO                
            }
            [array]$AccessArray2 = @()
            foreach ($Rule in $CurrentACL.Access) {
                $PSO = [PSCustomObject]@{
                    FileSystemRights  = $Rule.FileSystemRights
                    AccessControlType = $Rule.AccessControlType
                    IdentityReference = $Rule.IdentityReference
                    IsInherited       = $Rule.IsInherited
                    InheritanceFlags  = $Rule.InheritanceFlags
                    PropagationFlags  = $Rule.PropagationFlags
                }
                $AccessArray2 += $PSO                
            }

            $Diff = Get-DifferenceBetweenArrays -FirstArray $AccessArray1 -SecondArray $AccessArray2
            If ($Diff.count -gt 0) {
                $RulesIsEqual = $False
            }
        }     
        
        # if ($FileACL.owner -ne $Owner) {
        #     $CurrentACL.SetOwner([System.Security.Principal.NTAccount]"$Owner")
        #     Write-Host "Set owner [$Owner]."
        #     $RulesIsEqual = $False
        # }
        
        if (!$RulesIsEqual) {
            #$Rights | Select-Object * | Format-Table -AutoSize
            #(Get-Item $ItemPath).SetAccessControl($CurrentACL)    
            Set-Acl -Path $ItemPath -AclObject $CurrentACL
            Add-ToLog -Message "Permissions changed." -logFilePath $Global:gsScriptLogFilePath -display -status "Info" -level ($Global:gsParentLevel + 1)
        }
        Else {
            Add-ToLog -Message "Permissions are equal to model." -logFilePath $Global:gsScriptLogFilePath -display -status "Info" -level ($Global:gsParentLevel + 1)
        }
    }

    $DistinctFilePath = $Global:ACLArray | Where-Object { $_.Folder -eq $false } | Select-Object Path -Unique
    Foreach ($Item in $DistinctFilePath) {
        $ItemPath = $Item.path
        Add-ToLog -Message "Processing object [$ItemPath]." -logFilePath $Global:gsScriptLogFilePath -display -status "Info" -level ($Global:gsParentLevel + 1)
        $CurrentACL = Get-Acl $ItemPath

        [void]$CurrentACL.SetAccessRuleProtection($true, $false) # Delete inheritance  

        $ACLs = $Global:ACLArray | Where-Object { $_.path -eq $ItemPath }
        [array]$Rights = @()
        Foreach ($Acl in $ACLs) {  
            if ($Acl.mode -eq $Global:Modes.replace) {  
                $ACLToRemove = $CurrentACL.Access | Where-Object { ($_.IsInherited -eq $false) -and ($_.IdentityReference -eq $Acl.Acl[0].IdentityReference) }       
                foreach ($Item1 in  $ACLToRemove) {
                    [void]$CurrentACL.RemoveAccessRule($Item1) 
                } 
            }
            
            $Rights += $Acl.ACL   
                   
            if ($Acl.mode -eq $Global:Modes.replace) {
                $CurrentACL.SetAccessRule($Acl.ACL) 
            }
            Else {
                $CurrentACL.AddAccessRule($Acl.ACL)  
            }

            $Owner = $Global:Owner #$Acl.owner
        }  
        
        $FileACL = Get-Acl $ItemPath
        
        $RulesIsEqual = $False

        If ($FileACL.Access.count -eq $CurrentACL.Access.count) {
            $RulesIsEqual = $true        
            [array]$AccessArray1 = @()
            foreach ($Rule in $FileACL.Access) {
                $PSO = [PSCustomObject]@{
                    FileSystemRights  = $Rule.FileSystemRights
                    AccessControlType = $Rule.AccessControlType
                    IdentityReference = $Rule.IdentityReference
                    IsInherited       = $Rule.IsInherited
                    InheritanceFlags  = $Rule.InheritanceFlags
                    PropagationFlags  = $Rule.PropagationFlags
                }
                $AccessArray1 += $PSO                
            }
            [array]$AccessArray2 = @()
            foreach ($Rule in $CurrentACL.Access) {
                $PSO = [PSCustomObject]@{
                    FileSystemRights  = $Rule.FileSystemRights
                    AccessControlType = $Rule.AccessControlType
                    IdentityReference = $Rule.IdentityReference
                    IsInherited       = $Rule.IsInherited
                    InheritanceFlags  = $Rule.InheritanceFlags
                    PropagationFlags  = $Rule.PropagationFlags
                }
                $AccessArray2 += $PSO                
            }

            $Diff = Get-DifferenceBetweenArrays -FirstArray $AccessArray1 -SecondArray $AccessArray2
            If ($Diff.count -gt 0) {
                $RulesIsEqual = $False
            }
        }    

        # if ($FileACL.owner -ne $Owner){
        #     $CurrentACL.SetOwner([System.Security.Principal.NTAccount]"$Owner")
        #     Write-Host "Set owner [$Owner]."
        #     $RulesIsEqual = $False
        # }
        
        if (!$RulesIsEqual) {
            #$Rights | Select-Object * | Format-Table -AutoSize
            #(Get-Item $ItemPath).SetAccessControl($CurrentACL)
            Set-Acl -Path $ItemPath -AclObject $CurrentACL
            Add-ToLog -Message "Permissions changed." -logFilePath $Global:gsScriptLogFilePath -display -status "Info" -level ($Global:gsParentLevel + 1)
        }
        Else{
            Add-ToLog -Message "Permissions are equal to model." -logFilePath $Global:gsScriptLogFilePath -display -status "Info" -level ($Global:gsParentLevel + 1)
        }
    }
}
Else{
    Add-ToLog -Message "There is no [$ACLFile] or [$RolesFile] for project [$PathToFolder]." -logFilePath $Global:gsScriptLogFilePath -display -status "Error" -level ($Global:gsParentLevel + 1)
}

################################# Script end here ###################################
. "$($Global:gsGlobalSettingsPath)\$($Global:gsSCRIPTSFolder)\Finish.ps1"
