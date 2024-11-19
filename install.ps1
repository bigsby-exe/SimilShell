$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))){
    Write-Error "This script needs to be run as admin"
    break
}

# $sourceFolder = Read-Host "Enter source "
write-Host "Enter location of PowerShell files and profiles (e.g. OneDrive folder)"
write-host "This needs to have a profile.ps1 at the root level"
$destinationFolder = Read-Host "Location"

$Modules_source = Join-Path -Path $folderPath -ChildPath "\Modules"
$Modules_destination = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"

Robocopy $Modules_source $Modules_destination /MIR /FFT /Z /W:5

$taskName = "SyncFolders"
$action = New-ScheduledTaskAction -Execute "robocopy" -Argument "`"$Modules_source`" `"$Modules_destination`" /MIR /FFT /Z /W:5"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Description "Sync folders using Robocopy"

$profileFilePath = $PROFILE.AllUsersAllHosts

if (!(Test-Path -Path $destinationFolder)) {
    New-Item -Path $destinationFolder -ItemType Directory
}
$similprofile = Join-Path -Path $folderPath -ChildPath "profile.ps1"

$lineToAdd = ". $similprofile"
if (Test-Path $profileFilePath) {
    Add-Content -Path $profileFilePath -Value $lineToAdd
} else {
    $lineToAdd | Set-Content -Path $profileFilePath
}

#$profileScriptPath = "C:\ps\profile.ps1"
#$lineToAdd = 'Write-Host "It works!"'
#if (!(Test-Path $profileScriptPath)) {
#    $lineToAdd | Set-Content -Path $profileScriptPath
#}

#New-Item -ItemType Directory -Path C:\ps\Modules -Force
#$key = (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').OpenSubKey('Environment', $true)
#$path = $key.GetValue('PSModulePath','','DoNotExpandEnvironmentNames')
#$path += ';C:\ps\Modules'
#$key.SetValue('PSModulePath',$path,[Microsoft.Win32.RegistryValueKind]::ExpandString)