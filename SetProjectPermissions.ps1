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
    [string]$ScriptRoot
)

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
Function Set-NTFSAccess ($Path, $Acl) {
    if (Test-Path $Path) {
        $Object = Get-Item -Path $Path              
        foreach ($Role in $Global:LocalRoles) {
            if ($Role.name -eq $Acl.role){                    
                if ($Acl.mode -eq $Global:Modes.replace) {                    
                    if ($Acl.Right -ne $Global:Rights.deny) {
                        $RuleType            = "Allow"
                        $Rights              = $Acl.Right

                    }
                    Else {
                        $RuleType            = "Deny"
                        $Rights              = $Global:Rights.Modify
                    }
                    
                    if ($Object.PSIsContainer) {
                        $InheritSettings     = "ContainerInherit, ObjectInherit"  
                    }
                    Else{
                        $InheritSettings     = "None" 
                    }
                    
                    $user                = $Role.Member                    
                    $PropagationSettings = "None"
                    $Permissions         = $user, $Rights, $InheritSettings, $PropagationSettings, $RuleType
                    $AccessRule          = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permissions                    
                    $PSO = [PSCustomObject]@{
                        Path   = $Path
                        Folder = $Object.PSIsContainer
                        ACL    = $AccessRule
                        Owner  = $Acl.owner.value
                    } 
                    $Global:Array += $PSO
                }
            }
        }
    }

}
if (!$ScriptRoot){
    $ScriptRoot = $Global:PathToAnalyzedFolder
    Clear-Host
}


$MyScriptRoot = Get-WorkDir

Get-VarsFromFile    "$MyScriptRoot\Vars.ps1"
Initialize-Logging   $MyScriptRoot "Latest"

[string]$ACLFile   = "$ScriptRoot\ACL\ACL.xml"
[string]$RolesFile = "$ScriptRoot\ACL\Roles.csv"

if ((Test-Path $ACLFile) -and (Test-Path $RolesFile)){
    
    Add-ToLog -Message "Set NTFS permissions to project [$ScriptRoot]." -logFilePath $Global:LogFilePath -display -status "Info"
    [array] $Global:LocalRoles  = @()

    $Global:LocalRoles = Import-Csv -path $RolesFile -Encoding utf8
    $ACL = Import-Clixml $ACLFile 

    [array] $Global:Array = @()
    foreach ($item in $ACL){
        Set-NTFSAccess $item.Path $item  
    }

    $DistinctFolderPath = $Global:Array | Where-Object { $_.Folder -eq $true } | Select-Object Path -Unique
    Foreach ($Item in $DistinctFolderPath) {
        $ItemPath = $Item.path
        Add-ToLog -Message "Proceed object [$ItemPath]." -logFilePath $Global:LogFilePath -display -status "Info"
        $CurrentACL = Get-Acl $ItemPath

        [void]$CurrentACL.SetAccessRuleProtection($true, $false) # Delete inheritance  

        $ACLToRemove = $CurrentACL.Access | Where-Object { $_.IsInherited -eq $false}       
        foreach ($Item1 in  $ACLToRemove){
            [void]$CurrentACL.RemoveAccessRule($Item1) 
        } 

        $ACLs = $Global:Array | Where-Object { $_.path -eq $ItemPath }
        [array]$Rights = @()
        Foreach ($Acl in $ACLs) {  
            $Rights += $Acl.ACL          
            $CurrentACL.SetAccessRule($Acl.ACL) 
            $Owner = $Acl.owner
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
        
        if ($FileACL.owner -ne $CurrentACL.owner) {
            $CurrentACL.SetOwner($Owner)
            $RulesIsEqual = $False
        }
        
        if (!$RulesIsEqual) {
            $Rights | Select-Object * | Format-Table -AutoSize
            Set-Acl -Path $ItemPath -AclObject $CurrentACL
            Add-ToLog -Message "Permissions changed." -logFilePath $Global:LogFilePath -display -status "Info"
        }
        Else {
            Add-ToLog -Message "Permissions are equal to model." -logFilePath $Global:LogFilePath -display -status "Info"
        }
    }

    $DistinctFilePath = $Global:Array | Where-Object { $_.Folder -eq $false } | Select-Object Path -Unique
    Foreach ($Item in $DistinctFilePath) {
        $ItemPath = $Item.path
        Add-ToLog -Message "Proceed object [$ItemPath]." -logFilePath $Global:LogFilePath -display -status "Info"
        $CurrentACL = Get-Acl $ItemPath

        [void]$CurrentACL.SetAccessRuleProtection($true, $false) # Delete inheritance  

        $ACLToRemove = $CurrentACL.Access | Where-Object { $_.IsInherited -eq $false }       
        foreach ($Item1 in  $ACLToRemove) {
            [void]$CurrentACL.RemoveAccessRule($Item1) 
        } 

        $ACLs = $Global:Array | Where-Object { $_.path -eq $ItemPath }
        [array]$Rights = @()
        Foreach ($Acl in $ACLs) {  
            $Rights += $Acl.ACL
            $CurrentACL.SetAccessRule($Acl.ACL) 
            $Owner = $Acl.owner
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

        if ($FileACL.owner -ne $CurrentACL.owner){
            $CurrentACL.SetOwner($Owner)
            $RulesIsEqual = $False
        }
        
        if (!$RulesIsEqual) {
            $Rights | Select-Object * | Format-Table -AutoSize
            Set-Acl -Path $ItemPath -AclObject $CurrentACL
            Add-ToLog -Message "Permissions changed." -logFilePath $Global:LogFilePath -display -status "Info"
        }
        Else{
            Add-ToLog -Message "Permissions are equal to model." -logFilePath $Global:LogFilePath -display -status "Info"
        }
    }
    Add-ToLog -Message "Permissions set." -logFilePath $Global:LogFilePath -display -status "Info"
}
Else{
    Add-ToLog -Message "There is no [$ACLFile] or [$RolesFile] for project [$ScriptRoot]." -logFilePath $Global:LogFilePath -display -status "Error"
}