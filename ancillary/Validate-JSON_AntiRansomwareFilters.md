31 Dec 2019, Wishing you a better and brighter New Year

For additional info:
Get-Help Validate-JSON_AntiRansomwareFilters.ps1

This is a little filter validation utility I whipped up when I noticed that I downloaded a filter that had an escaped line feed(LF)/new line in it. FSRM did import the filter but converted the LF to a space.

This utility will validate the input filters, output the bad ones, and optionally write a JSON with a clean filters attribute.

No other attributes are filtered at this time. Let me know if you would like that implemented.