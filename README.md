# FSRM-Anti-ransomware
PowerShell and Python scripts to help you fight ransomware using both known filespecs and zero-day resistant honey traps.

Works with Windows Server 2012 and above, Python 3.6.x and above, and PowerShell 4 and above. There is a way to make it work with PowerShell 3 but you'll have to edit the script and be certain you're logged in as admin. Rather than hack the script just install WMF 5.1. It's strongly suggested on Windows Server 2012 (r1), suggested for Windows 2012r2, and already installed for Windows 2016 and above.

I just uploaded these files and, as is typical in many software development projects, I haven't written the documentation yet. I'll get notes written and uploaded very soon, but in the meantime send me a message and I'll get you going. Also be sure to read all those usage notes at the top of the FSRM-Anti-ransomware.ps1.

The FSRM-Anti-ransomware.ps1 script writes detailed messages to the Windows Application Event Log. That's the place to start if you're having trouble getting this installed.

Getting Started:

Download this repository as a zip file. Unzip to a directory named "C:\Program Files\FSRM Anti-ransomware"

Install Python 3.7.x or higher for "all users" and make sure it's on the path.

As Administrator - open a PowerShell prompt, change to the new directory, and run AntiransomwareFiltersMerge.py.

Still as Adminstrator - run FSRM-Anti-ransomware.ps1 and follow the prompts for a basic installation. You may use customized presets and place them in the NameHere-Custom-PreLoad-FSRM-Anti-ransomware.ps1 script so you don't have to type all that out every time.

That's the very sparse quick start. I'll get very detailed instructions done sooner rather than later.

Be sure to keep a close eye on these project files. This is under active development and I have plenty of to-dos to get to.

Jason Kreisler

18 Oct 2019
