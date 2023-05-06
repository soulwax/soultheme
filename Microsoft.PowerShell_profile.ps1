$DevPath = "D:\workspace\"
# SSH KEYS
$BLUESIX_KEY = "C:\Users\{0}\.ssh\blue6" -f $env:USERNAME
$STRATO_KEY = "C:\Users\{0}\.ssh\strato" -f $env:USERNAME
$WORK_MAIN_KEY = "C:\Users\{0}\.ssh\WORK_MAIN" -f $env:USERNAME
$OneDrivePath = "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Personal" # These are the registry keys for OneDrive so we can hardcode the path
$OneDriveBusinessPath = "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1\" # Same, but for OneDrive Business
$WorkspacePath = "D:\Workspace"
# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# open ssh connection to cloud.blue6.org as user cirrus using CLOUD_VM_PRIV_KEY and port 23582
function sshblue6 { ssh -i $BLUESIX_KEY -p 23582 cirrus@blue6.org }
function sshstrato { ssh -i $STRATO_KEY -p 23582 soulwax@bluesix.cloud }

function sshbc { ssh -i $WORK_MAIN_KEY -p 22 ssh_p.braincon.biz@p.braincon.biz }
function sshbct { ssh -i $WORK_MAIN_KEY -p 22 ssh_t.braincon.biz@p.braincon.biz }


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

if (Test-Path $OneDrivePath) {
    $onedrive = Get-ItemProperty -Path $OneDrivePath
    New-PSDrive -Name OneDrive -PSProvider FileSystem -Root $onedrive.UserFolder -Description "OneDrive"
    function onedrive { Push-Location OneDrive:\ }

    Remove-Variable onedrive
}

# Creates a OneDrive for Business shortcut, if it exists in registry
if (Test-Path $OneDriveBusinessPath) {
    $onedriveBiz = Get-ItemProperty -Path $OneDriveBusinessPath
    New-PSDrive -Name Business -PSProvider FileSystem -Root $onedriveBiz.UserFolder -Description "OneDrive Business"
    function business { Push-Location Business:\ }

    Remove-Variable onedriveBiz
}


if (Test-Path $WorkspacePath) {
    New-PSDrive -Name Work -PSProvider FileSystem -Root $WorkspacePath -Description "Workspace"
    function Work { Push-Location Work:\ }
}

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
        Start-Process "$psHome\pwsh.exe" -Verb runAs -ArgumentList $argList
    }
    else {
        Start-Process "$psHome\pwsh.exe" -Verb runAs
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



# Set-PSReadlineOption -Color @{
#     "Command" = [ConsoleColor]::Green
#     "Parameter" = [ConsoleColor]::Gray
#     "Operator" = [ConsoleColor]::Magenta
#     "Variable" = [ConsoleColor]::White
#     "String" = [ConsoleColor]::Yellow
#     "Number" = [ConsoleColor]::Blue
#     "Type" = [ConsoleColor]::Cyan
#     "Comment" = [ConsoleColor]::DarkCyan
# }

# Dracula Prompt Configuration
# Import-Module posh-git
# $GitPromptSettings.DefaultPromptPrefix.Text = "$([char]0x2192) " # arrow unicode symbol
# $GitPromptSettings.DefaultPromptPrefix.ForegroundColor = [ConsoleColor]::Green
# $GitPromptSettings.DefaultPromptPath.ForegroundColor =[ConsoleColor]::Cyan
# $GitPromptSettings.DefaultPromptSuffix.Text = "$([char]0x203A) " # chevron unicode symbol
# $GitPromptSettings.DefaultPromptSuffix.ForegroundColor = [ConsoleColor]::Magenta
# # Dracula Git Status Configuration
# $GitPromptSettings.BeforeStatus.ForegroundColor = [ConsoleColor]::Blue
# $GitPromptSettings.BranchColor.ForegroundColor = [ConsoleColor]::Blue
# $GitPromptSettings.AfterStatus.ForegroundColor = [ConsoleColor]::Blue

# Set the default theme for the PowerShell
# $theme = "clean-detailed" // pretty ok
$theme = "soulbubble"

$previousOutputEncoding = [Console]::OutputEncoding
[Console]::OutputEncoding = [Text.Encoding]::UTF8
try {
    & ([ScriptBlock]::Create((oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\$theme.omp.json" --print) -join "`n"))
} finally {
    [Console]::OutputEncoding = $previousOutputEncoding
}
# Import the Chocolatey Profile that contains the necessary code to enable
# tab-completions to function for `choco`.
# Be aware that if you are missing these lines from your profile, tab completion
# for `choco` will not function.
# See https://ch0.co/tab-completion for details.
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
  Import-Module "$ChocolateyProfile"
}
