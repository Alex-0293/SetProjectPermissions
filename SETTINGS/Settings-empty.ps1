# Rename this file to Settings.ps1

    [array]  $global:FoldersToApplyPath   = @()         # Path to run on.
    [string] $Global:PathToAnalyzedFolder = ""          # Selected project path.
    $Global:Owner                         = ""          # Owner account.

######################### no replacement ######################## 
    [string]$Global:SetPermissionErrors = "$ProjectRoot\$($Global:gsLOGSFolder)\$($($Global:gsScriptBaseFileName))Errors.log" # This script error file path.
    [string]$Global:RoleMembersFile     = "$ProjectRoot\$($Global:gsDATAFolder)\ROLES\Members.ps1"                # Role members file path.
    [string]$Global:RolesFileName       = "Roles.csv"                # Role members file path.
    [string]$Global:AccessFileName      = "Access.csv"                # Role members file path.
    [string]$Global:OwnerFileName       = "Owner.csv"                # Role members file path.

    [array] $Global:Roles                 = @()                                                         # Roles array.
    [array] $global:FoldersToIgnoreName   = @(".vscode", "TemplateProject")                             # Ignored folder names.
    [bool]  $Global:RegenerateACL         = $True                                                       # Regenerate ACL files?

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

$FileRoles = Get-ChildItem -path "$ProjectRoot\$($Global:gsDATAFolder)\ROLES" -File -Filter "role*.ps1"  
foreach ($Role in $FileRoles) {
    Get-SettingsFromFile  $Role.fullName
}


[bool] $Global:LocalSettingsSuccessfullyLoaded = $true

# Error trap
trap {
    $Global:LocalSettingsSuccessfullyLoaded = $False
    exit 1
}
