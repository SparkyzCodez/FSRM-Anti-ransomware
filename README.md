# FSRM-Anti-ransomware
PowerShell and Python scripts to help you fight ransomware using both known filespecs and zero-day resistant honey traps.

Works with Windows Server 2012 and above, Python 3.7.x and above, and PowerShell 4 and above. There is a way to make it work with PowerShell 3 but you'll have to edit the script and be certain you're logged in as admin. Rather than hack the script just install WMF 5.1. It's required on Windows Server 2012 (r1) and suggested for Windows 2012r2. For Windows 2016 and above you're already covered.

I just uploaded these files and, as is typical in many software development projects, I haven't written the documentation yet. I'll get notes written and uploaded very soon, but in the meantime send me a message and I'll get you going. Also be sure to read all those usage notes at the top of the FSRM-Anti-ransomware.ps1.

The FSRM-Anti-ransomware.ps1 script writes detailed messages to the Windows Application Event Log. That's the place to start if you're having trouble getting this installed.
