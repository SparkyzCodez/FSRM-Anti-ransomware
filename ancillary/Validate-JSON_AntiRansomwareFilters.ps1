<#
.Synopsis
Reads a JSON file with a filters section, substitutes simple text for wildcards, and uses the OS to validate a legal filespec using Test-Path.

.Description
The input file is assumed to be a JSON file. It also assumes the existence of an FSRM-Anti-ransomware and Experiant style filters attribute.

Each filter will first have the wildcard characters * and ? replaced with some simple text. Then we call Test-Path using the -IsValid switch to test for legality on that system's OS.

Any invalid/illegal file names will be barfed out. Keep in mind that carriage returns and line feeds are invalid but will be displayed in this script's output.

-WriteCleaned will write a cleaned file named cleaned.json. Because PowerShell sucks I'm not able to split the file name into pieces and reassemble it with "-cleaned" appended to the base file name. That is only available in PowerShell 6 but we can rely on that being available, even in the latest Windows 10. Merde.

Notes:
We are not doing any regex or testing against a static list of characters. We're simply relying on the OS on which this is running to do the testing.

We're also not testing the input file for JSON validity. If the input file isn't JSON or doesn't have a correctly formatted filter attribute we'll simply choke and exit.
.Link
https://github.com/SparkyzCodez/FSRM-Anti-ransomware
https://fsrm.experiant.ca/
#>

param(
    [Parameter(Mandatory=$true)][string]$Path,
    [switch]$WriteCleaned
    )
$CurrentVersion = "1.0.0"

Write-Host "Version $CurrentVersion`nTesting filters in file: $Path`n"
$json = Get-Content $Path
$PSobj = ConvertFrom-Json $json
$alpha = @()
$omega = @()
$PSobj.filters | ForEach-Object {
    $TestFspec = $_
    # look through $TestFspec for * and ?, and replace with legal placeholder characters, this will sub legal characters for the legal wildcards
    $TestFspec = $TestFspec -replace '\*','ZZ'  # since a * can match more then one character let's use more than one substitute character
    $TestFspec = $TestFspec -replace '\?','Y'   # ? only matches a single character so we'll use just one substitue character
    if (Test-Path -IsValid -Path $TestFspec)
        {
        $alpha += $_
        }
    else
        {
        $omega += $_ + "`n"
        }
    }

# If there are fewer validated fspecs than we read in
if ($alpha.Count -lt $PSobj.filters.Count)
    {
    # now barf a warning with the invalid filter strings
    Write-Host "Barf!!! Invalid filespecs:"
    Write-Host "$omega"

    # write a cleaned file
    if ($WriteCleaned.IsPresent)
        {
        $OPpath = "cleaned.json"
        $PSobj.filters = $alpha
        $json = ConvertTo-Json $PSobj
        # we're writing blindly and clobbering any clean file that already exists, impolite!!!
        $json | Out-File -FilePath $OPpath -Encoding UTF8 -Force
        }
    }
else 
    {
    Write-Host "Nothing to Barf! All test filenames are valid on this OS."
    }
