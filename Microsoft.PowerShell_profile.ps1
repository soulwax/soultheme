##### SET THE FOLLOWING VARIABLES TO YOUR OWN VALUES / NEEDS, THE SCRIPT MAKES THE BEST OUT OF WHAT YOU GIVE IT ####################################
##### POSH THEME FILE ##############################################################################################################################
# $poshThemeFile = "C:\Users\soulwax\Documents\PowerShell\Themes\material.omp.json"
# $poshThemeFile = "C:\Users\{0}\Documents\PowerShell\Themes\emodipt-extend.omp.json" -f $env:USERNAME
# $poshThemeFile = "F:\OneDrive\Dokumente\PowerShell\Themes\tokyo.omp.json"
# oh-my-posh --init --shell pwsh --config "F:\OneDrive\Dokumente\PowerShell\Themes\tokyo.omp.json" | Invoke-Expression
# oh-my-posh init pwsh --config "C:/Users/soulwax/AppData/Local/Programs/oh-my-posh/themes/bubblesline.omp.json" | Invoke-Expression



# $themeName = "soul-term"
# $poshThemeFile = "C:\Users\{0}\Documents\PowerShell\Themes\{1}.omp.json" -f $env:USERNAME, $themeName

# if (Test-Path $poshThemeFile -PathType Leaf) {
#     oh-my-posh init pwsh --config $poshThemeFile | Invoke-Expression
# }
#$poshThemeFile = "D:\Development\PowerShell\soulwax.theme.json"

####################################################################################################################################################

##### USER ENVIRONMENT VARIABLES ###################################################################################################################
$WorkFoldersPath = "$env:USERPROFILE\Work Folders"
$AlternateDevPath = "C:\Users\{0}\Documents\Workspace" -f $env:USERNAME
$DevPath = "C:\Users\{0}\Root\workspace" -f $env:USERNAME
$OneDrivePath = "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Personal" # These are the registry keys for OneDrive so we can hardcode the path
$OneDriveBusinessPath = "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1\" # Same, but for OneDrive Business
$DevRootFolderPath = "$env:USERPROFILE\Root\workspace" -f $env:USERNAME
$IcloudPath = "C:\Users\{0}\iCloudDrive" -f $env:USERNAME
# $ONEDRIVE_PERSONAL = "G:\OneDrive"
# $OneDriveHomePath = "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business2\"
#####################################################################################################################################################

###### THE CODE FOLLOWING THIS LINE WORKS WITH THE VARIABLES ABOVE THIS LINE ########################################################################

### PowerShell template profile 
### Version 1.04 - soulwax <discord: soulwax#5586>
### From https://gist.github.com/timsneath/19867b12eee7fd5af2ba
###
### This file should be stored in $PROFILE.CurrentUserAllHosts
### If $PROFILE.CurrentUserAllHosts doesn't exist, you can make one with the following:
###    PS> New-Item $PROFILE.CurrentUserAllHosts -ItemType File -Force
### This will create the file and the containing subdirectory if it doesn't already 
###
### As a reminder, to enable unsigned script execution of local scripts on client Windows, 
### you need to run this line (or similar) from an elevated PowerShell prompt:
###   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
### This is the default policy on Windows Server 2012 R2 and above for server Windows. For 
### more information about execution policies, run Get-Help about_Execution_Policies.

# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If so and the current host is a command line, then change to red color 
# as warning to user that they are operating in an elevated context
if (($host.Name -match "ConsoleHost") -and ($isAdmin)) {
    $host.UI.RawUI.BackgroundColor = "DarkRed"
    $host.PrivateData.ErrorBackgroundColor = "White"
    $host.PrivateData.ErrorForegroundColor = "DarkRed"
    Clear-Host
}

# SSH KEYS
$SIGHEIM_KEY = "C:\Users\{0}\.ssh\sigheim" -f $env:USERNAME
$CLEVER_ROSALIND_KEY = "C:\Users\{0}\.ssh\clever_rosalind" -f $env:USERNAME
$BLUESIX_KEY = "C:\Users\{0}\.ssh\blue6" -f $env:USERNAME
# $STRATO_KEY = "C:\Users\{0}\.ssh\strato" -f $env:USERNAME
$WORK_MAIN_KEY = "C:\Users\{0}\.ssh\WORK_MAIN" -f $env:USERNAME
$VELOUR_STRATO_KEY = "C:\Users\{0}\.ssh\velour-strato" -f $env:USERNAME

# open ssh connection to cloud.blue6.org as user cirrus using CLOUD_VM_PRIV_KEY and port 23582
function sshblue6 { ssh -i $BLUESIX_KEY -p 23582 cirrus@cloud.blue6.org }
function sshmadtec { ssh -i $CLEVER_ROSALIND_KEY -p 23582 soulwax@madtec.org }
function sshsigheim { ssh -i $SIGHEIM_KEY -p 23582 soulwax@sigheim.de }
function sshstrato { ssh -i $VELOUR_STRATO_KEY -p 23582 velour-velvet@bluesix.cloud }

function sshbc { ssh -i $WORK_MAIN_KEY -p 22 ssh_p.braincon.biz@p.braincon.biz }
function sshbct { ssh -i $WORK_MAIN_KEY -p 22 ssh_t.braincon.biz@p.braincon.biz }


# function "cdnc" to change directory to the Nextcloud folder in G:\bluecloud
function cdnc { Set-Location "G:\bluecloud" }




# Useful shortcuts for traversing directories
function cd... { Set-Location ..\.. }
function cd.... { Set-Location ..\..\.. }
function cddev { Set-Location "$DevPath\$args" } # Example usage: cddev Flutter -> Opens the "Flutter folder on the previously defined development folder path"
function cdold { Set-Location "$OldDevPath\$args" } # Example usage: cdold web
# -> This will take you to C:\Users\{your username}\Documents\Development\web immediately
function cpdev { Copy-Item -Recurse -Force $args $DevPath } # Example usage: cpdev .\SomeFolder C:\Users\{your username}\Documents\Backup\ 
# -> This will copy the web folder from the Development folder to the fictitious backup folder in Documents

# Compute file hashes - useful for checking successful downloads and verifying integrity
function md5 { Get-FileHash -Algorithm MD5 $args } 
function sha1 { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args } 

# Quick shortcut to start notepad with the current file
function n { notepad $args }
# Quick shortcut to start vscode with the current file
function vs { code $args }

# Drive shortcuts
function HKLM: { Set-Location HKLM: }
function HKCU: { Set-Location HKCU: }
function Env: { Set-Location Env: }

function self { 
    # Return this file as full path
    code $PROFILE
 }


# Creates drive shortcut for Work Folders, if current user account is using it
if (Test-Path $WorkFoldersPath) {
    New-PSDrive -Name Work -PSProvider FileSystem -Root "$env:USERPROFILE\Work Folders" -Description "Work Folders"
    function Work: { Set-Location Work: }
}

if (Test-Path $OneDrivePath) {
    $onedrive = Get-ItemProperty -Path $OneDrivePath
    New-PSDrive -Name OneDrive -PSProvider FileSystem -Root $onedrive.UserFolder -Description "OneDrive"
    function OneDrive: { Set-Location OneDrive: }
    Remove-Variable onedrive
}

# Creates a OneDrive for Business shortcut, if it exists in registry
if (Test-Path $OneDriveBusinessPath) {
    $onedrive = Get-ItemProperty -Path $OneDriveBusinessPath
    New-PSDrive -Name Business -PSProvider FileSystem -Root $onedrive.UserFolder -Description "OneDrive Business"
    function Business: { Set-Location Business: }
    Remove-Variable onedrive
}

# if (Test-Path $OneDriveHomePath) {
#     $onedrive = Get-ItemProperty -Path $OneDriveHomePath
#     New-PSDrive -Name Home -PSProvider FileSystem -Root $onedrive.UserFolder -Description "OneDrive Home"
#     function Home: { Set-Location Home: }
#     Remove-Variable onedrive
# }




if (Test-Path $IcloudPath) {
    New-PSDrive -Name iCloud -PSProvider FileSystem -Root $IcloudPath -Description "iCloud Drive"
    function Icloud: { Set-Location iCloud: }
}
# echo ""
# echo "Name           Used (GB)     Free (GB) Provider      Root"
# function dash { Write-Host "----           ---------     --------- --------      ----" }
# dash

if (Test-Path $DevPath) {
    New-PSDrive -Name Dev -PSProvider FileSystem -Root $DevPath -Description $DevRootFolderPath
    function Dev: { Set-Location Dev: }
}
elseif (Test-Path $DevPathGer) {
    New-PSDrive -Name Dev -PSProvider FileSystem -Root $DevPath -Description "Workspace"
    function Dev: { Set-Location Dev: }
} 
elseif (Test-Path $AlternateDevPath) {
    New-PSDrive -Name Dev -PSProvider FileSystem -Root $DevPath -Description "Codespace" # or we...
    function Dev: { Set-Location Dev: }
}



# # Creates a CloudBank shortcut, if it exists in registry
# if (Test-Path $CloudBankPath) {
#     New-PSDrive -Name CloudBank -PSProvider FileSystem -Root $CloudBankPath -Description "CloudBank"
#     function CloudBank: { Set-Location CloudBank: }
# }

# Set up command prompt and window title. Use UNIX-style convention for identifying 
# whether user is elevated (root) or not. Window title shows current version of PowerShell
# and appends [ADMIN] if appropriate for easy taskbar identification
function prompt { 
    if ($isAdmin) {
        "[" + (Get-Location) + "] # " 
    }
    else {
        "[" + (Get-Location) + "] $ "
    }
}

$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
if ($isAdmin) {
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}

# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs {
    if ($args.Count -gt 0) {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    }
    else {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}

# Simple function to start a new elevated process. If arguments are supplied then 
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
function admin {
    if ($args.Count -gt 0) {   
        $argList = "& '" + $args + "'"
        Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $argList
    }
    else {
        Start-Process "$psHome\powershell.exe" -Verb runAs
    }
}

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights. 
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin


# Make it easy to edit this profile once it's installed
function Edit-Profile {
    if ($host.Name -match "ise") {
        $psISE.CurrentPowerShellTab.Files.Add($profile.CurrentUserAllHosts)
    }
    else {
        notepad $profile.CurrentUserAllHosts
    }
}

# $theme = "clean-detailed" // pretty ok
$theme = "material"

$previousOutputEncoding = [Console]::OutputEncoding
[Console]::OutputEncoding = [Text.Encoding]::UTF8
try {
    oh-my-posh init pwsh --config $env:POSH_THEMES_PATH/$theme.omp.json | Invoke-Expression
} finally {
    [Console]::OutputEncoding = $previousOutputEncoding
}

Set-PSReadlineOption -Color @{
    "Command" = [ConsoleColor]::Green
    "Parameter" = [ConsoleColor]::Gray
    "Operator" = [ConsoleColor]::Magenta
    "Variable" = [ConsoleColor]::White
    "String" = [ConsoleColor]::Yellow
    "Number" = [ConsoleColor]::Blue
    "Type" = [ConsoleColor]::Cyan
    "Comment" = [ConsoleColor]::DarkCyan
}
# Dracula Prompt Configuration
Import-Module posh-git
$GitPromptSettings.DefaultPromptPrefix.Text = "$([char]0x2192) " # arrow unicode symbol
$GitPromptSettings.DefaultPromptPrefix.ForegroundColor = [ConsoleColor]::Green
$GitPromptSettings.DefaultPromptPath.ForegroundColor =[ConsoleColor]::Cyan
$GitPromptSettings.DefaultPromptSuffix.Text = "$([char]0x203A) " # chevron unicode symbol
$GitPromptSettings.DefaultPromptSuffix.ForegroundColor = [ConsoleColor]::Magenta
# Dracula Git Status Configuration
$GitPromptSettings.BeforeStatus.ForegroundColor = [ConsoleColor]::Blue
$GitPromptSettings.BranchColor.ForegroundColor = [ConsoleColor]::Blue
$GitPromptSettings.AfterStatus.ForegroundColor = [ConsoleColor]::Blue
