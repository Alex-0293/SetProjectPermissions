
    [array]  $global:FoldersToApplyPath   = @()         # Path to run on.
    [string] $Global:PathToAnalyzedFolder = ""          # Selected project path.
    $Global:Owner                         = ""          # Owner account.

######################### no replacement ######################## 
    [string]$Global:SetPermissionErrors   = "$ProjectRoot\$LOGSFolder\$($ScriptBaseFileName)Errors.log" # This script error file path.
    [string]$Global:RoleMembersFile       = "$ProjectRoot\$DATAFolder\ROLES\Members.ps1"                # Role members file path.
    [array] $Global:Roles                 = @()                                                         # Roles array.
    [array] $global:FoldersToIgnoreName   = @(".vscode", "TemplateProject")                             # Ignored folder names.
    [bool]  $Global:RegenerateACL         = $True                                                       # Regenerate ACL files?

$FileRoles = Get-ChildItem -path "$ProjectRoot\$DATAFolder\ROLES" -File -Filter "role*.ps1"  
foreach ($Role in $FileRoles){
    Get-SettingsFromFile  $Role.fullName
}

$Global:Rights = [PSCustomObject]@{
    FC      = "FullControl"
    Modify  = "Modify"
    Read    = "Read"
    Write   = "Write"    
    Execute = "ExecuteFile"
    Deny    = "Deny"
}

$Global:Modes = [PSCustomObject]@{
    Replace = "Replace"
    Append  = "Append"
}
