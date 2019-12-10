# Installation and Setup.md

!!!!
Update 10Dec2019
please note: This document is currently incomplete. We're making progress but I didn't want to hold it back until it's done. The sections with information are rough but I think they're close to complete. Comments are very welcome.

!!!!

[placeholder link to videos](https://github.com/SparkyzCodez/FSRM-Anti-ransomware)

## Prerequisites - Python 3.7 or higher, PowerShell 4 or higher, and a dedicated domain admin equivalent account
The actual steps that I use to configure some of these prerequisites are in separate instructions.

- You must have Administrator privileges and all PowerShell commands in these instructions must be run in a "run as Administrator" shell.
- Python must be installed for all users and it should be on the path.
- If you use a fully patched version of Windows 2012r2 or higher then you have PowerShell 4 or higher installed. At a PowerShell prompt execute ***Get-PSVersion*** or ***$PSVersionTable*** to find your version.
- For Windows 2012(r1) users it's a little more complicated, but not much.  There are separate instructions to upgrade your PowerShell by installing Windows Management Framework (WMF) 5.1. There's also a work around to use version 3 but I really discourage that. Upgrading is easy and WMF 5.1 is very stable.
- You'll need a dedicated domain admin equivalent user account for the recurring scheduled tasks. The account should only be used for FSRM Anti-ransomware.
- Your user account must have run Internet Explorer at least once on each server to which you are installing. All the JSON download options require an initialized Internet Options configuration. This is a Windows limitation.

## Install files to ***C:\Program Files***
First we need to get the files copied to the system. The files can be put anywhere on any of the disks, **BUT** the file permissions under "\Program Files\" are already just the way we need them. I've only tested this directory so your mileage may vary if you put the files elsewhere.

One of the steps is to rename the extracted directory. GitHub insists on putting the branch name in the Zip file's name, but I don't use that.

Steps:

1. download from [GitHub SparkyzCodez/FSRM-Anti-ransomware] (https://github.com/SparkyzCodez/FSRM-Anti-ransomware/archive/master.zip) and save or copy it to ***C:\Program Files***
2. Extract the contents. You should have a directory called ***FSRM-Anti-ransomware-master*** (may vary based on the branch you download)
3. Rename the directory to ***FSRM-Anti-ransomware***

## Update the combined-extended JSON file with the latest ransomware filespecs

- Open a PowerShell prompt, change to the install directory, execute *AntiransomwareFiltersMerge.py* with the appropriate options. Use the *--help* flag to get detailed usage information.

You will end up with a file that looks something like *combined-extended-20191206_104615.json*. The file name is date stamped. The date is big endian followed by a Python-ish number of seconds.

You may leave the file name as-is or you may change the word "extended" to something else that's more meaningful for you. **You must put your custom name between the dashes.** Leave everything else in the file name alone. For some of my clients I just use a one word company name, but for more complicated setups where I want different exceptions based on the server's use I'll use the server's name. For example I may change the name to *combined-exampleco-20191206_104615.json* or *combined-fileserver1-20191206_104615.json*.

## Everything Search - Screen for existing ransomware files and avoid future false postitives
The purpose of this step is to find all the files on your system that match ransomware file names. Run the *EverythingSearchForRansomware.py* script and generate a report in whatever format is convenient for you (text, csv, or JSON). Your OS drive will have matches that are completely safe. *.rat* files are one example. If you are already infected with ransomware or have leftovers from a previous attack you will find all those files with this process. And this is fast. You can search 5 million file names in less than 3 minutes.

Note: The JSON format report has a number of attributes, and at first glance it's not clear where you should look. Focus on the "filters-FSRMmatched" attribute. These are the matches that the FSRM engine is actively trying to match. We'll cover how to use the other attributes in a seperate deep dive document.

Once you've screened all the files you found, and remediated them if necessary, you're ready to come up with your exceptions to add to your JSON file. We'll cover exceptions handing in much deeper detail in a separate doc. For now just run the search and find out what you have.

1. From an elevated PowerShell prompt change your install directory.
2. Run *EverythingSearchForRansomware.py* with the appropriate options. Use the *--help* flag to get detailed usage information. You will probably be most interested in the *--fnamesubstring* (if you customized your JSON file name) and *--reporttoscreen --reporttext* options to get started. The resulting reports will be date stamped.

**If you find actual ransomware files DON'T DELETE THEM.** You want to keep anything you find and document it thoroughly for forensic and perhaps insurance purposes. If you're not an IT security expert then find one. The crime scene evidence must be preserved. In addition, any suspicious files you find can be left in place when you turn on FSRM. They will only trigger FSRM actions if they are accessed.

## First run - install FSRM
## Setup your honey pots - optional
## Second run - create and apply ransomware and honey pot templates
## Configure Windows task scheduler for daily updates
The settings listed below are the final settings. At the end of this list I'll put a few troubleshooting tricks and traps, so be sure to read all the way to the end.

This is by far the most work in the entire process. In the future I will come up with a PowerShell script or create some XML templates to take the sting out of this.

1. create folder under Task Scheduler Library called ***FSRM-Anti-ransomware*** then click on it
2. Create a Task (not basic) for fetching new filter filespecs
    + General tab
        * name: ***Anti-ransomware Filters Fetch Updates and Merge***
        * security options: Run as your dedicated FSRM Anti-ransomware domain admin account
        * security options: Run whether user is logged on or not
        * configure for: Windows Server 2012 (or highest available)
    +  Triggers tab - new trigger
        *  begin: On a schedule
        *  settings: Daily, 3:55:00 AM, recur every day, don't sync across time zones (use whatever time makes sense to you)
        *  advanced setting: Delay task for up to 4 minutes
            -  just type over whatever is in the drop down
            -  this is so we're polite to fsrm.experiant.ca
        * advanced setting: Stop task if it runs longer than 30 minutes (it should never even take 1 minute to run)
        * advanced setting: Enabled (I've missed this one. Don't be me.)
    + Actions tab - new action (pay close attention to these details, especially which quotes to use)
        * action: Start a program
        * program/script: ***python***
        * add arguments: ***"C:\Program Files\FSRM-Anti-ransomware\AntiransomwareFiltersMerge.py" -n extended***
            - the additional parameters for the script go outside the quotes
            - important! change -n parameter to match your JSON file name substring
        * start in: ***C:\Program Files\FSRM-Anti-ransomware\\***
            - no quotes!
            - trailing backslash is optional
    + Conditions tab
        * clear all the check boxes
    + Settings tab
        * Allow task to be run on demand
        * Run task as soon as possible after scheduled start is missed
        * Stop the task if it runs longer than: 1 hour
        * If the running task does not end when requested, for it to stop
        * If the task is already running: Do not start a new instance
    + Click OK, add the password for you dedicated domain admin account, and run the task on demand, make sure the Last Run Result says it completed successfully
3. Create a Task (not basic) for refreshing the file screens
    + General tab
        * name: ***Anti-ransomware Screen Refresh Daily***
        * security options: Run as your dedicated FSRM Anti-ransomware domain admin account
        * security options: Run whether user is logged on or not
        * configure for: Windows Server 2012 (or highest available)
    +  Triggers tab - new trigger
        *  begin: On a schedule
        *  settings: Daily, 4:00:00 AM, recur every day, don't sync across time zones (use whatever time makes sense to you)
        * advanced: Stop task if it runs longer than 30 minutes (it should never even take 1 minute to run)
        * advanced: Enabled (I've missed this one. Don't be me.)
    + Actions tab - new action (pay close attention to these details, especially which quotes to use)
        * action: Start a program
        * program/script: ***powershell***
        * add arguments: ***& 'C:\Program Files\FSRM-Anti-ransomware\NameHere-Custom-PreLoad-FSRM-Anti-ransomware.ps1'***
            - mind the single quotes!
        * start in: ***C:\Program Files\FSRM-Anti-ransomware\\***
            - no quotes!
            - trailing backslash is optional
    + Conditions tab
        * clear all the check boxes
    + Settings tab
        * Allow task to be run on demand
        * Run task as soon as possible after scheduled start is missed
        * Stop the task if it runs longer than: 1 hour
        * If the running task does not end when requested, for it to stop
        * If the task is already running: Do not start a new instance
    + Click OK, add the password for you dedicated domain admin account, and run the task on demand - look in the Windows Application event log for FSRM-AntiRansomwareScript EventID 999 that indicates successful completion (large file servers can take several minutes to complete)

##### Task Scheduler Troubleshooting

- Check that your single quotes, double quotes, and lack of quotes exactly match these instructions. You must wrap your PowerShell script name in the arguments field with single quotes because there's a space in the path name. Double quotes don't work. (Double quotes do work for the Python script names though.)
- Switch to *Run only when user is logged on* on the General tab. This will cause everything to run in an interactive window. That doesn't mean the window will stay open, but you'll at least see something happen.
- To keep a PowerShell script windows open you use the *-NoExit* option. This will keep your PowerShell window open after the script has run so you can see what went wrong. You will have ***powershell*** for your Program/Script and your argument will put ***-NoExit*** right before the ampersand. For example: ***-NoExit & 'C:\Program Files\FSRM-Anti-ransomware\ExampleCo-Custom-PreLoad-FSRM-Anti-ransomware.ps1'***
- You can try setting ***Run with highest privileges*** on the General tab if everything else seems right but the script still won't run.
- If Python refuses to launch try using the full path to the Python interpreter. For example, your full path to Python should look something like this *C:\Program Files\Python38\python.exe* . If it is installed somewhere under *C:\Users* then it's not installed for all users. You'll need to reinstall it.
- If PowerShell refuses to launch try using the full path to the PowerShell interpreter. Assuming *C:* is your OS drive, your path is always *C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe*. (No, you don't have version 1.x. Yes Microsoft hard codes the path. I bet Macrosloth regrets some of their life choices now.)
- Enable All Tasks History for the task scheduler to get very detailed status. You probably won't need this for the FSRM PowerShell script because it already puts detailed logging in the Windows-Application event log.

