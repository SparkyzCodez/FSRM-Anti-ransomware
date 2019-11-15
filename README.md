Update note 15Nov2019:
Corrected main script name in custom loader template script.

Update note 7Nov2019:
Fixed a case sensitivity bug in EverythingSearchForRansomware.py. Change from case sensitive search to case insensitive so that it more closely matches how Windows FSRM matches file names. This did not impact the actual FSRM file screening in any way.

# FSRM-Anti-ransomware
PowerShell and Python scripts to help you fight ransomware using both known filespecs and zero-day resistant honey traps.

Min requirements: Windows Server 2012 (r1), Python 3.6, PowerShell 4

There are three components to this suite of tools:
1. FSRM-Anti-ransomware.ps1 - PowerShell script that installs and updates FSRM services and file screens, use daily
2. AntiransomwareFiltersMerge.py - Python script to manage and keep ransomware filespecs up to date
3. EverythingSearchForRansomware.py - Python script to search your drives for files matching ransomware filespecs

Windows 2012r1 doesn't have PowerShell 4 by default. It's easy to add though by installing WMF 5.1. (If you have Windows 2012 r1 or r2 you should install this anyway.) If you absolutely cannot upgrade your PowerShell there is a workaround that will let you run PowerShell 3. See the notes.

I'll get documentation written and uploaded very soon (I promise!), but in the meantime send me a message and I'll get you going. Also be sure to read all those usage notes at the top of the FSRM-Anti-ransomware.ps1.

The FSRM-Anti-ransomware.ps1 script writes detailed messages to the Windows Application Event Log. Look there to help troubleshoot any issues you run into.


Getting Started:

Download this repository as a zip file. Unzip to a directory named "C:\Program Files\FSRM Anti-ransomware"

Install Python 3.6.x or higher for "all users" and make sure it's on the path. Python 3.7 and above is recommended.

As Administrator - open a PowerShell prompt, change to the new directory, and run AntiransomwareFiltersMerge.py to update your combined-extended... JSON file with the latest ransomware filespecs from Experiant.

Still as Adminstrator - run FSRM-Anti-ransomware.ps1 and follow the prompts for a basic installation. You may use customized presets and place them in the NameHere-Custom-PreLoad-FSRM-Anti-ransomware.ps1 script so you don't have to type all that out every time.

That's the very sparse quick start. I'll get very detailed instructions done sooner rather than later.

Be sure to keep a close eye on these project files. This is under active development and I have plenty of to-dos to get to.

Jason Kreisler

8 Nov 2019
