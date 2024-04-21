$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))){
    Write-Error "This script needs to be run as admin"
    break
}

$sourceFolder = Read-Host "Enter source"
$destinationFolder = "C:\ps"

Robocopy $sourceFolder $destinationFolder /MIR /FFT /Z /W:5

$taskName = "SyncFolders"
$action = New-ScheduledTaskAction -Execute "robocopy" -Argument "`"$sourceFolder`" `"$destinationFolder`" /MIR /FFT /Z /W:5"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Description "Sync folders using Robocopy"

$profileFilePath = $PROFILE.AllUsersAllHosts
$lineToAdd = '. C:\ps\profile.ps1'
if (Test-Path $profileFilePath) {
    Add-Content -Path $profileFilePath -Value $lineToAdd
} else {
    $lineToAdd | Set-Content -Path $profileFilePath
}

$profileScriptPath = "C:\ps\profile.ps1"
$lineToAdd = 'Write-Host "It works!"'
if (!(Test-Path $profileScriptPath)) {
    $lineToAdd | Set-Content -Path $profileScriptPath
}

New-Item -ItemType Directory -Path C:\ps\Modules -Force
$key = (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').OpenSubKey('Environment', $true)
$path = $key.GetValue('PSModulePath','','DoNotExpandEnvironmentNames')
$path += ';C:\ps\Modules'
$key.SetValue('PSModulePath',$path,[Microsoft.Win32.RegistryValueKind]::ExpandString)