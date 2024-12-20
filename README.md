19 Dec 2024
Officially archiving this repo.

17 Jul 2024
The company that had live updates of ransomware file names went offline with their service a few years ago. Without a replacement this project is dead. I hope you can use it as a springboard for whatever projects you're working on.

16 Jan 2020

The testing branch 2.5 looked good and it is now merged into the master.

I've also refreshed the combined-extended-20200116_000000.json file by removing the two illegal filespecs. One was __\*.\_NEMTY\_<\*>\___ and this one won't come back because it's not included in the Experiant download any more.

The other filespec is __\*.support(at)anonymous-service.cc.ppdddp(line return here)Unusual__, which I've mangled a bit so that it displays here. This one is still included in the Experiant JSON data so it will keep getting put back into our exended JSON data too. The FSRM-Anti-ransomware.ps script will filter it out before it ever gets to our file groups. I'm still adding functionality to the AntiransomwareFiltersMerge.py script to handle this more gracefully. Take a look at the issues for this project to keep up with the latest details.

Progress Note: 31 Dec 2019

I wish you a happy and prosperous New Year in 2020.

Now to business:

We're skipping FSRM-Anti-ransomware version 2.4.x and proceeding directly to 2.5.x BUT it's not uploaded to Git just yet. I'll post a message here when I get it completed and uploaded. __UPDATE: This is now in the master branch and we're on version 2.5.__

There's a new triggered script to deny permissions to shares that now includes event log messages and a fail safe in case the FSRM event timers are set to anything but 0 minutes (critical setting). The location of the triggered script defaults to the same directory as the FSRM-Anti-ransomare script too, but it's still configurable. An additional feature in the triggered script is that you will be able to use it to unlock a user's account by passing the ***-Unlock*** switch to the script. It also outputs messages to the Windows event log.

The event logging source is now ***FSRM Anti-ransomware Suite*** instead of FSRM-AntiRansomwareScript. Since there's a number of moving parts, including three PowerShell scripts and a couple Python apps, I think this better reflects the nature of this project.

Finally, the filters from Experiant dated 30 Dec 2019 had something unexpected in them. One filter has an escaped new-line in it. This is what it looks like in the JSON data "\*.support@anonymous-service.cc.ppdddp\nUnusual". It's the backslash-n just in front of *Unusual*. The new line is importing into the FSRM file group as a space, but that seems more accidental than intentional. I've written a little PowerShell utility that will screen the filters on your file system using your live file system's limitations, and optionally write a cleaned version of the JSON. It's in the ancillary folder. Let me know what you think.

For those of you playing at home, this is a regex that will find an illegal character in a Windows file name:

[\x00-\x1f]|\||"|<|>|:|\*|\?|\\|\/

You can also use PowerShell's Test-Path with the -IsValid switch for your own testing. It's what I used in the ancillary script.

Update notes: 26Dec2019:

Switched the sample Windows Sorted File Names archive from Zip to 7zip because the 7zip utility is more consistent about unzipping files with a leading space in their names. Added files with leading dots in their file names to archive too. Refreshed extended JSON file.

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

Download this repository as a zip file. Unzip to a directory named "C:\Program Files\FSRM-Anti-ransomware"

Install Python 3.6.x or higher for "all users" and make sure it's on the path. Python 3.7 and above is recommended.

As Administrator - open a PowerShell prompt, change to the new directory, and run AntiransomwareFiltersMerge.py to update your combined-extended... JSON file with the latest ransomware filespecs from Experiant.

Still as Adminstrator - run FSRM-Anti-ransomware.ps1 and follow the prompts for a basic installation. You may use customized presets and place them in the NameHere-Custom-PreLoad-FSRM-Anti-ransomware.ps1 script so you don't have to type all that out every time.

That's the very sparse quick start. I'll get very detailed instructions done sooner rather than later.

Be sure to keep a close eye on these project files. This is under active development and I have plenty of to-dos to get to.

Cheers,
Sparky Z Codez

8 Nov 2019
