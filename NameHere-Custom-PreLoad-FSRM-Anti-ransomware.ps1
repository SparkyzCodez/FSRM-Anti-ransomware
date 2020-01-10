#Requires -Version 4 -RunAsAdministrator

<#
.Notes
This script must be in the same directory as FSRM-Anti-ransomware.ps1

.Synopsis
This script is a convenience launcher template for the FSRM-Anti-ransomware.ps1 script.
It does not take any command line parameters. You must edit this file.

.Description
This script requires PowerShell 4 or higher and administrative permissions. See the "Installation and Setup.md" for using PowerShell 3 work around information.
FSRM-Anti-ransomware.ps1 takes a lot of paramters. This script is a convenient way to set all your preferred parameters in one place. You may copy and rename this script to whatever you like. I recommend that you change "NameHere" to something meaninful such as a company name or a server name. The only restriction is that this script must be in the same directory as FSRM-Anti-ransomware.ps1. 
You must edit this file before using it. The current settings in this are only for example purposes.

.Link
https://github.com/SparkyzCodez/FSRM-Anti-ransomware
#>
begin
    {
    # Edit this variable with the parameters you want to use every time. Use this loader in the task scheduler.
    # !! You must escape all dollar signs with back tick. eg. $true must appear as `$true
    # !! you must wrap any parameter strings that contain spaces with single quotes, eg. '[Admin Email]'
    $ScriptParameters = "-SMTPServer youremailserver.example.org -AdminEmailTo needtoknow@example.org -JSONfnamesubstring example -RansomwareTemplateIsActive `$false -HoneyPotDirectoryNamePattern ?ITDept_DoNotTamperWithContents -HoneyPotDirectoryNameWildcardMatchesLeadingDot `$false -TriggeredScriptEmailTo '[Admin Email]' -ApplyRansomewareScreenToShares `$false  -YesAllTheVariablesAreSetHowIWant `$false"
    }
# do not edit anything in the process block
process
    {
    # spaces in the ScriptToRun string are a problem because the string may already have spaces wrapped in single quotes.
    # This is the work around. We're going old school and setting the cwd.
    Set-Location $PSScriptRoot
    $ScriptToRun = ".\FSRM-Anti-ransomware.ps1 $ScriptParameters"
    Write-Output "`nLoader (this) script: $PSCommandPath`n`nScript to call: $ScriptToRun`n"
    Invoke-Expression -Command "$ScriptToRun"
    }