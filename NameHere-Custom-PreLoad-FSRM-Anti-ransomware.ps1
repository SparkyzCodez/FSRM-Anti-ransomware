# This script must be in the same directory as Install-and-Update-FSRM-Anti-ransomware.ps1
begin
    {
    # Edit this variable with the parameters you want to use every time. Use this loader in the task scheduler.
    # !! You must escape all dollar signs with back tick. eg. $true must appear as `$true
    # !! you must wrap any parameter strings that contain spaces with single quotes, eg. '[Admin Email]'
    $ScriptParameters = "-SMTPServer youremailserver.example.org -AdminEmailTo needtoknow@example.org -JSONfnamesubstring example -RansomwareTemplateIsActive `$false -HoneyPotDirectoryNamePattern ?YourTechnologyDept_PleaseIgnoreContents -TriggeredScriptEmailTo '[Admin Email]' -ApplyRansomewareScreenToShares `$false  -YesAllTheVariablesAreSetHowIWant `$true"
    }
# do not edit anything in the process block
process
    {
    # spaces in the ScriptToRun string are a problem because the string may already have spaces wrapped in single quotes.
    # This is the work around. We're going old school and setting the cwd.
    Set-Location $PSScriptRoot
    $ScriptToRun = ".\Install-and-Update-FSRM-Anti-ransomware.ps1 $ScriptParameters"
    Write-Output "`nLoader (this) script: $PSCommandPath`n`nScript to call: $ScriptToRun`n"
    Invoke-Expression -Command "$ScriptToRun"
    }