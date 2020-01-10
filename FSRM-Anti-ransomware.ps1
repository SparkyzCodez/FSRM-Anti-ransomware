#Requires -Version 4 -RunAsAdministrator


<#
.Notes
Name: FSRM-Anti-ransomware.ps1

-> Important: This file must be Unicode UTF-8 encoded for the embedded ransomware file names to render properly. Also, save this with a BOM so that Windows will "guess" the format correctly.
Compare the two lines just below. One is Unicode and the other ASCII. The two lines should be legible and look very similar to each other. If not then you've lost Unicode encoding. Note: the PowerShell Get-Help cmdlet doesn't know how to render Unicode. Use a text editor or the PowerShell ISE to read the file.
	Α-Uиịϲоԁḙ-Ω		(Unicode with mix of Greek, Cyrillic, and Latin characters, and begins with Greek alpha and ends with Greek omega)
	A-Unicode-O		(ASCII, plain text)
(A BOM should never be necessary with UTF-8 Unicode, but the PowerShell ISE still needs it to correctly detect Unicode encoding. Be sure this file has a BOM.)

-> Important: You must leave the FSRM global setting Notification Limits -> Command notification (minutes): set to 0 (zero). It will be reset each time this script runs.
If you must have this set to something else then you'll need to reset the FSRM service in the triggered scripts each time they run.
You "should" also have the event notification set to 0 so that each event goes to the Windows event log
The reason for this is because we're using a mechanism (FSRM file screens) that were originally intended only for notification messages. We are re-purposing it for security actions. Be strict!

-> Important: This script assumes that you DO NOT already have file screens applied to drives/shares that will be captured by this script.
Only one screen is allowed per resource (share,drive,directory). If other screens have been applied to the same shares / drive points then this script will fail at creating new file screens in those places.

-> Important: When you run this script be sure you read and remediate all errors and warnings shown on the screen and shown in the Windows Application event log.
When this script runs correctly there will be no warnings or errors.
exception:
	There may be warnings (but not errors) about the email configuration when you run this the first time.
	The warnings will clear when you rerun this script a second time, after which the warnings will stay cleared.

Edit the variables in the param section or in a custom pre-load script to match your SMTP setup and admin email. Use the included script "NameHere-Custom-PreLoad-FSRM-Anti-ransomware.ps1" as a template.

If FSRM is already installed you should still run this script. It will take care of the mandatory settings that we need for ransomware detection.

Special note for installing FSRM on Windows 2012 and 2012r2
After installing FSRM you will probably need to reboot the OS manually. Take note of the message on the screen telling you to do so.
When you run this script the second time to install all the file screens you may still see quite a few errors. Just stop and then restart the FSRM service.
You can avoid all this trouble by either installing WMF 5.1 or manually installing FSRM and rebooting first. This is for Windows 2012 versions only.
	requires .NET 4.5.2 or higher, will install with lower versions without error but functionality will be impacted
	if you are fully patched then you will be running at least v4.8.x even on W2012r1
	check version installed here:
		HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full

PowerShell version 3 workaround - Yes, it's possible to run this script under PowerShell 3 but you must be certain you're running it as administrator. Here's what to do in two simple steps:
	1. remove the "# Requires -Version 4" line from the top of this script
	2. change the test "If ($PSVersionTable.PSVersion.Major -lt 4)" to "If ($PSVersionTable.PSVersion.Major -lt 3)"
	3. You should really consider installing WMF 5.1. I've never seen any negative effects from doing so.

If the global settings in the FSRM management console look empty right after you've run this script then just restart the management console to make them show.
The settings are there, you just can't see them because there's no refresh option at the top level of the FSRM manager.	

The option to download a filters list from https://fsrm.experiant.ca assumes that you have initialized your Internet Explorer.
The Invoke-WebRequest command uses the Internet Explorer engine. Internet Explorer must be setup and your settings must allow the download. Don't know Edge impact.

.Synopsis
This script installs and configures FSRM upon the first run, and configures and refreshes Anti-ransomware file screens on all subsequent runs.

Use "Get-Help -Detailed" to see detailed paramter descriptions.

.Description
Requirements:
Windows Server 2012 (r1, a.k.a. Windows 6.2) or above with all updates applied
PowerShell 4 or above strongly recommended, but PowerShell 3 can be made to work (see version 3 workaround information in the script notes).

This script will perform an initial installation of the File Server Resource Manager (FSRM) if it's not already installed. On subsequent runs this script will reconfigure FSRM as needed including setting the CommandNotificationLimit to the mandatory value of 0, create file groups, create templates for file matching and honey pot screens, and create file screens for all specified shares and drives. Because this is a complex security configuration you need to understand all the parameters used in this script then set the YesAllTheVariablesAreSetHowIWant parameter to $True.

It is essential that this file is always encoded in UTF-8-BOM. To verify Unicode encoding just open this script in a text editor and read the verifcation text near the top.

.Link
https://github.com/SparkyzCodez/FSRM-Anti-ransomware
#>


param(
	# This is the SMTP you will use for FSRM. You must set this variable manually. The default value is just a place holder. Only supports unauthenticated, unencrypted email at this time.
	[string]$SMTPServer = "127.0.0.1",

	# This is the "from" email address that will be used in every FSRM triggered email. By default we'll build a string using the computer name and the domain name. This especially suitable for servers that are domain joined. You may replace this with any email address string you choose. For stand-alone or custom configurations use something like -EmailFrom "FSRM-Triggered@example.com".
	[string]$EmailFrom = "FSRM-"+(Get-CIMInstance -Class CIM_ComputerSystem).Name+"@"+(Get-CIMInstance -Class CIM_ComputerSystem).Domain,

	# These are the email addresses that notifications will be sent to. Notification emails may be sent to more than one recipient; seperate multiple recipients with a semicolon (eg. "admin1@example.com;admin2@example.com")
	[string]$AdminEmailTo = "securityadmin@example.com",

	# This enables legacy mode direct downloading of the filters filespecs in JSON format. While it is possible to download filters directly, it is better to use the included "AntiransomwareFiltersMerge.py" Python script that generates JSON input data and carries all your additional options forward. The legacy download will download a "combined.json" file containing filters AND modify the filter list based on your local legacy IncludeList.txt and SkipList.txt files which must be in the same directory as this script. (This script will not relocate the text files like other legacy scripts did.) Default: $false
	[bool]$LegacyDownloadFiltersJson = $false,

	# This is the URL used my the legacy download mode. This data is kindly provided by Experiant.
	[string]$LegacyDownloadFiltersJsonURL = "https://fsrm.experiant.ca/api/v1/combined",  # they do a great job keeping their filters up to date

	# This is a substring used in the input JSON file's name. It allows you to use customized versions of the files. The default is "extended" and the file name will be similar to combined-extended-20191123_090937.json. For example, you could use a substring variation to make file names like combined-accountingserver-20191123_090937.json or combined-DetroitHQ-20191123_090937.json. Do not add any dashes to this text because they are used for substring parsing!
	[string]$JSONfnamesubstring = "extended",

	# Be sure you understand what "passive" and "active" mean in the context of FSRM before overriding this setting. Active sends email alerts and actively blocks access to files (good for production files, prevents any ransomware files from being created, may still allow encryption of existing files). Passive sends email alerts but does not block access to files (good for honey pots so you can do forensics on encrypted files and ransom requests). Default: $true
	[bool]$RansomwareTemplateIsActive = $true,

	# This is the name template you'll use for your honey pot directories. Since the bad guys can read this too, you must customize this. Do not use this default; it's just a place holder. Keep the '?' to match the leading sorting characters in the included sample zip file. These directories must be read/write and easily accessible. Instruct your users to avoid accessing these honey pot directories. Hiding these directories from your users would defeat the whole purpose.
	[string]$HoneyPotDirectoryNamePattern = "?ITDept_DoNotTamperWithContents",

	# This allows the Honey Pot directory name template to wildcard match a leading dot. A Windows "?" wildcard will not match a leading dot. This is a work around to address this behavior. Especially useful if your shares are accessed by Linux or Mac/Unix clients. Default: $false
	[bool]$HoneyPotDirectoryNameWildcardMatchesLeadingDot = $false,


	# These are the email address FSRM variables used for notifications when a file screen is triggered. Note: You DO NOT enter email addresses here; you use specific FSRM variables. See the included "FSRM email form variables.txt" or the FSRM online help for the definitions of these FSRM variables. You may not want to notify the owner. If not then do this instead: $TriggeredScriptEmailTo = "[Admin Email]"
	[string]$TriggeredScriptEmailTo = "[Admin Email];[Source Io Owner Email]",

	# This causes ransomware file screens to be applied to the roots of all drives except C:. (It could adversely affect OS performance to screen the entire OS drive. Instead we will screen any shares found on the OS drive.)  Default: $true
	[bool]$ApplyRansomewareScreenToDrives = $true,

	# This causes the ransomware file screens to screen all "non-special" file shares except those any under the OS drive\Windows directories. Default: $true
	[bool]$ApplyRansomewareScreenToShares = $true,

	# This causes the existing file screens to be deleted and then be reapplied. This insures that all new shares are added to screening. Default: $true
	[bool]$RefreshRansomewareScreens  = $true,

	# This causes the Ransomware screens to rapidly disconnect the user's SMB session when triggered. General use shares should probably be disconnected quickly. Default: $true
	[bool]$RansomewareScreenRapidSMBdisconnect = $true,

	# This causes the honey pot file screens to be applied to all shared directories that match the HoneyPotDirectoryNamePattern filespec. Default: $true
	[bool]$ApplyHoneyPots = $true,

	# This causes the existing honey pot file screens to be deleted and then be reapplied. This insures that all new honey pot shares are added to screening. Default: $true
	[bool]$RefreshHoneyPots = $true,

	# This causes the Honey Pots screens to rapidly disconnect the user's SMB session when triggered. Honey pot shares should probably NOT be disconnected quickly. This will allow you to capture more compromised files for forensic purposes. Default: $false
	[bool]$HoneyPotsScreenRapidSMBdisconnect = $false,

	# The configuration of this script covers a lot of critically important security issues. Setting the following variable to $true is your acknowledgement that you understand all the settings in both the param() block at the top of this script and the additional variables at the top of the begin{} section of this script. (two locations) Default: $false
	# !!! The SMTP server and the EmailTo variables must be set to insure prompt notifications.
	# !!! The CommandNotificationLimit must be set to 0, the EventNotificationLimit should be set to 0, and both are hard coded in this script.
	# !!! script editing note: Do not make this variable mandatory/required as that would bypass event logging and information display.
	[bool]$YesAllTheVariablesAreSetHowIWant = $false
	)


function InstallUpdate-FSRMRansomwareScreening
{
Begin
	{
	# BEGIN - ADDITIONAL VARIABLES THAT NEED TO BE SET AND VALIDATED #
	$CurrentVersion = "2.5.0"

	# Leave these two event log variables just as they are unless you are quite sure you want the logging handled differently.
	$EventLog = "Application"
	# couldn't use two dashes in this source name, Window event loggin kept truncating the source name, no idea why
	$EventLoggingSource = "FSRM Anti-ransomware Suite"

	# These are default values from fsrm.experiant.ca. These are static and not updated too often. You can get started with these but you need to get the "AntiransomwareFiltersMerge.py" running in your task schedule to stay up to date.
	$RansomeWareFileGroupName = "RansomwareFnamesAndExt"
	$RansomewareRapidSMBdisconnectFlagholder = "" # will be populated later based on command line boolean

	# double check that this file is UTF-8, this embedded filters list contains names in Cyrillic, Portuguese, Spanish, Chinese, etc. see the top of this script
	# filters refresh date: 2019-12-30
	$FnameExtFilters = @("! ПРОЧТИ МЕНЯ !.html","!! RETURN FILES !!.txt","!!! HOW TO DECRYPT FILES !!!.txt","!!! READ THIS - IMPORTANT !!!.txt","!!!!!ATENÇÃO!!!!!.html","!!!!!SAVE YOUR FILES!!!!.txt","!!!!RESTORE_FILES!!!.txt","!!!-WARNING-!!!.html","!!!-WARNING-!!!.txt","!!!GetBackData!!!.txt","!!!INSTRUCTION_RNSMW!!!.txt","!!!README!!!*.rtf","!!!READ_IT!!!.txt","!!!READ_TO_UNLOCK!!!.TXT","!!!ReadMeToDecrypt.txt","!!!Readme!!!Help!!!.txt","!!!SAVE YOUR FILES!.bmp","!## DECRYPT FILES ##!.txt","!#_DECRYPT_#!.inf","!#_How_to_decrypt_files_#!","!#_How_to_decrypt_files_$!.txt","!-GET_MY_FILES-!.*","!=How_to_decrypt_files=!.txt","!DMALOCK3.0*","!Decrypt-All-Files-*.txt","!ENC","!GBLOCK_INFO.rtf","!INSTRUCTI0NS!.TXT","!OoopsYourFilesLocked!.rtf","!PEDANt_INFO!.rtf","!Please Read Me!.txt","!QH24_INFO!.rtf","!READ.htm","!README_GMAN!.rtf","!README_GRHAN!.rtf","!Recovery_*.html","!Recovery_*.txt","!SBLOCK_INFO!.rtf","!WannaDecryptor!.exe.lnk","!Where_are_my_files!.html","!_!email__ prusa@goat.si __!..PAYMAN","!_HOW_RECOVERY_FILES_!.txt","!_HOW_TO_RESTORE_*.txt","!_Notice_!.txt","!_RECOVERY_HELP_!.txt","!____________DESKRYPT@TUTAMAIL.COM________.rar","!_ИНСТРУКЦИЯ_!.txt","!back_files!.html","!how_to_unlock_your_file.txt","!readme.*","!satana!.txt","# DECRYPT MY FILES #.html","# DECRYPT MY FILES #.txt","# DECRYPT MY FILES #.vbs","# How to Decrypt Files.txt","# README.hta","###-READ-FOR-HELLPP.html","#DECP_README#.rtf","#HELP-DECRYPT-FCRYPT1.1#.txt","#HOW_DECRYPT_FILES#.html","#HOW_TO_UNRIP#.txt","#NEWRAR_README#.rtf","#README_GMAN#.rtf","#RECOVERY-PC#.*","#RECOVERY_FILES#.*","#RECOVERY_FILES#.txt","#_#ReadMe#_#.rtf","#_#WhatWrongWithMyFiles#_#.rtf","#_DECRYPT_ASSISTANCE_#.txt","#_RESTORING_FILES_#.TXT","$%%! NOTE ABOUT FILES -=!-.html","$RECYCLE.BIN.{*-*-*-*}","(encrypted)","(encrypted)*","* .tdelf","* .vCrypt1","*!DMAlock*","*!recover!*.*","*+recover+*.*","*-DECRYPT.html","*-DECRYPT.txt","*-Lock.onion","*-PLIIKI.txt","*-filesencrypted.html","*-recover-*.*","*-webmafia@asia.com_donald@trampo.info","*.!emc","*.#","*.##ENCRYPTED_BY_pablukl0cker##","*.##___POLICJA!!!___TEN_PLIK_ZOSTA","*.#Locky","*.#__EnCrYpTED_BY_dzikusssT3AM_ransomware!__#","*.*.[decrypt@files.mn].angus","*.*.[helpnetin@protonmail.com].com","*.*.[kenny.sarginson@aol.com].deal","*.*.[prndssdnrp@mail.fr].deuce","*.*.sell","*.*GEFEST","*.*cry","*.*crypto","*.*darkness","*.*exx","*.*kb15","*.*kraken","*.*locked","*.*locker*","*.*nochance","*.*obleep","*.+jabber-theone@safetyjabber.com","*...Files-Frozen-NEED-TO-MAKE-PAYMENT…","*..txt","*.0000","*.010001","*.0402","*.08kJA","*.0day","*.0riz0n","*.0wn3dyou","*.0x0","*.0x004867","*.0x009d8a","*.101","*.1500dollars","*.1999","*.1btc","*.1txt","*.1ywsmbo4","*.2048","*.24H","*.2cXpCihgsVxB3","*.2du1mj8","*.2k19","*.2k19sys","*.2lwnPp2B","*.2xx9","*.31342E30362E32303136*","*.31392E30362E32303136_*","*.3301","*.3674AD9F-5958-4F2A-5CB7-F0F56A8885EA","*.3P7m","*.3RNu","*.3nCRY","*.3ncrypt3d","*.3v3r1s","*.449o43","*.46d7k","*.490","*.491","*.492","*.4k","*.4rwcry4w","*.4x82N","*.509a49","*.59d49","*.619-300-6500","*.61yhi","*.63vc4","*.666","*.666decrypt666","*.686l0tek69","*.6FKR8d","*.6db8","*.707","*.725","*.726","*.73i87A","*.777","*.7h9r","*.7jo22z5m","*.7z.encrypted","*.7zipper","*.8637","*.888","*.8lock8","*.911","*.96e2","*.@decrypt2017","*.@decrypt_2017","*.A604AF9070","*.A95436@YA.RU","*.A9V9AHU4","*.ABAT","*.ABCDEF","*.ACTUM","*.ADMIN@BADADMIN.XYZ","*.ADR","*.AES","*.AES-NI","*.AES256","*.AFD","*.ANNABELLE","*.ARTEMY","*.ATLAS","*.AUDIT","*.AUF","*.AVco3","*.AYE","*.AZER","*.Acton","*.Acton.id[1AE26935-1085].[hadleeshelton@aol.com].Acton","*.Acuf2","*.Adame","*.AdolfHitler","*.Alcatraz","*.AlfaBlock","*.Alkohol","*.Amigo","*.AngleWare","*.Angus","*.Annabelle2","*.Apollon865","*.AreYouLoveMyRansFile","*.Armage","*.Artemis","*.Athena865","*.Atom","*.Aurora","*.B10CKED","*.BANKS","*.BARRACUDA","*.BAWSUOOXE","*.BB4-230-*","*.BD.Recovery","*.BDKR","*.BELGIAN_COCOA","*.BIG1","*.BIG4+","*.BMCODE","*.BONUM","*.BORISHORSE","*.BORISHORSE…","*.BRT92","*.BUGWARE","*.BUSH","*.BaLoZiN","*.BadNews","*.BarRax","*.Barak","*.Bear","*.BeethoveN","*.Bill_Clinton@derpymailorg","*.Bitconnect","*.BlackHat","*.BlackPink","*.BlackRouter","*.Blocked2","*.Blower@india.com","*.BtcKING","*.C0rp0r@c@0Xr@","*.CAGO","*.CASH","*.CCCRRRPPP","*.CEBER3","*.CHAK","*.CHE808","*.CHIP","*.CHRISTMAS","*.CIFGKSAFFSFYGHD","*.CIOP","*.CK","*.COCKROACH","*.COLORIT","*.CONFICKER","*.CONTACTUS","*.CONTACT_TARINEOZA@GMAIL.COM","*.COPAN","*.CQQUH","*.CQXGPMKNR","*.CRABSLKT","*.CRADLE","*.CROWN","*.CROWN!?","*.CRPTXXX","*.CRRRT","*.CRYPTED000007","*.CRYPTOBOSS","*.CRYPTOBYTE","*.CRYPTOSHIEL","*.CRYPTOSHIELD","*.CRYPTR","*.CRYZP","*.CTB2","*.CTBL2","*.CYBERGOD","*.CYRON","*.Caley","*.Calum","*.CerBerSysLocked0009881","*.Cerber_RansomWare@qq.com","*.Chartogy","*.Clop","*.CommonRansom","*.Contact_Here_To_Recover_Your_Files.txt","*.Crab","*.Cry128","*.Cry36","*.Cry9","*.CrySiS","*.CryptWalker","*.CryptedOpps","*.CryptoTorLocker2015!","*.Crypton","*.CyberSCCP","*.CyberSoldiersST","*.Cyclone","*.D00mEd","*.D2550A49BF52DFC23F2C013C5","*.DALE","*.DARKCRY","*.DATASTOP","*.DATAWAIT","*.DATA_IS_SAFE_YOU_NEED_TO_MAKE_THE_PAYMENT_IN_MAXIM_24_HOURS_OR_ALL_YOUR_FILES_WILL_BE_LOST_FOREVER_PLEASE_BE_REZONABLE_IS_NOT_A_JOKE_TIME_IS_LIMITED","*.DECP","*.DESYNC","*.DEUSCRYPT","*.DEXTER","*.DG","*.DHDR4","*.DIABLO6","*.DMR64","*.DOCM!Sample","*.DQXOO","*.DREAM","*.DS335","*.DeLpHiMoRiX!@@@@_@@_@_2018_@@@_@_@_@@@","*.DeLpHiMoRiX*","*.Deniz_Kızı","*.DiskDoctor","*.Djvuu","*.Do_not_change_the_file_name.cryp","*.Doxes","*.EGG","*.EMAN","*.EMAN50","*.EMPTY","*.ENCR","*.ERIS","*.ERIS!","*.ERROR","*.EV","*.EXTE","*.EZDZ","*.Elder","*.Email=[jacdecr@tuta.io]ID=[*].KRONOS","*.Email=[luciferenc@tutanota.com]ID=[*].odveta","*.EnCiPhErEd","*.EncrypTile","*.Encrypted","*.Encrypted5","*.Encrypted[BaYuCheng@yeah.net].XiaBa","*.Encrypted_By_VMola.com","*.Enter","*.EnyBenied","*.Epoblockl","*.Erenahen","*.ExpBoot","*.ExpBoot!","*.FASTBOB","*.FCrypt","*.FEROSUS","*.FFF","*.FIXT","*.FJ7QvaR9VUmi","*.FLATCHER3@INDIA.COM.000G","*.FREDD","*.FRS","*.FTCODE","*.FUNNY","*.Facebook","*.FailedAccess","*.FilGZmsp","*.File","*.FileSlack","*.Flux","*.Freezing","*.Frendi","*.Frivolity","*.Fuck_You","*.FuckedByGhost","*.G8xB","*.GBLOCK","*.GDCB","*.GEFEST","*.GETREKT","*.GG","*.GGGHJMNGFD","*.GILLETTE","*.GMAN","*.GMBN","*.GMPF","*.GORILLA","*.GOTHAM","*.GOTYA","*.GRANIT","*.GRHAN","*.GSupport3","*.Gefest3","*.GodLock","*.GrAnoSinSa","*.GrujaRS","*.HAPP","*.HCY!!","*.HELLO","*.HELPPME@INDIA.COM.ID83994902","*.HHFEHIOL","*.HILDA","*.HRM","*.HUSTONWEHAVEAPROBLEM@KEEMAIL.ME","*.HYENA","*.H_F_D_locked","*.Hades666","*.Hades666!","*.HakunaMatata","*.Harzhuangzi","*.Hermes","*.Hermes666","*.HeroesOftheStorm","*.Horriblemorning","*.Horros","*.Horse4444","*.Horsuke","*.How_To_Decrypt.txt","*.How_To_Get_Back.txt","*.I'WANT MONEY","*.ID-7ES642406.CRY","*.ILLNEST","*.INCANTO","*.INDRIK","*.INFOWAIT","*.ITLOCK","*.IWANT","*.Infinite","*.Ipcrestore","*.JAMES","*.JEEPERS","*.JFCWF","*.JKOUOGVG","*.JLCW2","*.JayTHL","*.JezRoz","*.Jumper","*.K8VfiZ","*.KARLS","*.KAxoAgY","*.KEYH0LES","*.KEYHOLES","*.KEYPASS","*.KEYZ","*.KEYZ.KEYH0LES","*.KICK","*.KK","*.KOK08","*.KOK8","*.KRAB","*.KRONOS","*.KUAJW","*.Kg9EX","*.Kiratos","*.L0CKED","*.L1LL","*.LAMBDA.LOCKED","*.LCKD","*.LDPR","*.LEGO","*.LGAWPULM","*.LIGHTNING","*.LIN","*.LOCK75","*.LOCKED.txt","*.LOCKED_BY_pablukl0cker","*.LOCKED_PAY","*.LOCKOUT","*.LOL!","*.LOLI","*.LOVE","*.LTML","*.LanRan*","*.LanRan2.0.5","*.Lazarus","*.Lazarus+!","*.LeChiffre","*.Locked-by-Mafia","*.Locked_file","*.Lockify","*.LolSec","*.LonleyEncryptedFile","*.Losers","*.Lost_Files_Encrypt","*.LoveYou","*.MATRIX","*.MAYA","*.MDEN","*.MDRL","*.MERRY","*.MIKOYAN","*.MMM","*.MMTeam","*.MOLE","*.MOLE00","*.MOLE01","*.MOLE02","*.MOLE03","*.MOLE04","*.MOLE66","*.MRCR1","*.MTC","*.MTXLOCK","*.MZ173801","*.MZ434376","*.MaMo434376","*.Malki","*.Marozka","*.Mcafee","*.Mercury","*.Mira","*.MyChemicalRomance4EVER","*.NEMTY_*","*.NEMTY_VFFXXXX","*.NEMTY_VFRLXV9","*.NEWRAR","*.NGSC","*.NHCR","*.NIGGA","*.NM4","*.NMCRYPT","*.NOBAD","*.NOLOST","*.NOOB","*.NOT","*.NOT_OPEN","*.NUMBERDOT","*.Nano","*.Navi","*.Neptune","*.Node0","*.Novosof","*.Nutella","*.O67NG","*.OBLIVION","*.OGONIA","*.OMG!","*.ONION","*.ONYC","*.ONYX","*.OOFNIK","*.OOOKJYHCTVDF","*.OQn1B","*.OTR","*.OXR","*.ObcKIn","*.OhNo!","*.Ordinal","*.Ox4444","*.PA-SIEM","*.PANDA","*.PAUSA","*.PAY","*.PAY_IN_MAXIM_24_HOURS_OR_ALL_YOUR_FILES_WILL_BE_PERMANENTLY_DELETED_PLEASE_BE_REZONABLE_you_have_only_1_single_chance_to_make_the_payment","*.PC-FunHACKED*","*.PEDANT","*.PEDO","*.PEGS1","*.PERSONAL_ID*","*.PHOBOS","*.PICO","*.PIRATE","*.PLANETARY","*.PLANT","*.PLIN","*.PLUT","*.PO1HG","*.POHU","*.POSHKODER","*.PRCP","*.PRIVAT66","*.PTGEPVEKM","*.PUMAX","*.PayDay","*.Persephone666!","*.Petya","*.Pig4444","*.PoAr2w","*.Pox","*.PrOtOnIs","*.PrOtOnIs.VaNdElIs","*.Prandel","*.Prodecryptor","*.Prt6aV9","*.Puma","*.QH24","*.Qtyu8vH5wDXf6OSWAm5NuA==ObcK","*.R.i.P","*.R16M01D05","*.R3K7M9","*.R4A","*.R4bb0l0ck","*.R5A","*.RAD","*.RADAMANT","*.RANSOM","*.RARE1","*.RASTAKHIZ","*.RDM","*.RDWF","*.REBL","*.REBUS","*.RECOVERYOURFILES","*.RENSENWARE","*.REVENGE","*.RJZUNA","*.RMCM1","*.ROGER","*.RRK","*.RSNSlocked","*.RSplited","*.RaaS","*.Ransed","*.RansomAES","*.RansomMine","*.ReadTheInstructions","*.Read_Me.Txt","*.RedEye","*.Reyptson","*.Rooster865qq","*.Rooster865qqZ","*.Ryuk","*.SALSA222","*.SANTANA","*.SATANA","*.SAVEYOURDATA","*.SAVEfiles","*.SBLOCK","*.SDEN","*.SENRUS17","*.SEPSIS","*.SERP","*.SEVENDAYS","*.SF","*.SHARK","*.SHRUG","*.SHRUG2","*.SKJDTHGHH","*.SKYSTARS","*.SLAV","*.SOLO","*.SONIC","*.SPCT","*.STOP","*.STOPDATA","*.SUPERCRYPT","*.SUSPENDED","*.SYMMYWARE","*.SaMsUnG","*.SaherBlueEagleRansomware","*.Satyr","*.SaveTheQueen","*.SaveTheQueenING","*.Scorpion","*.SecureCrypte","*.SecureCrypted","*.Server","*.ShutUpAndDance","*.Sifrelendi","*.Sil3nt5pring","*.Silent","*.SpartCript","*.Srpx","*.Stinger","*.SySS","*.TABGH","*.TEST","*.TGIF","*.THANATOS","*.THDA","*.TMS5","*.TR","*.TRMT","*.TROLL","*.TROLL,","*.TRUE","*.TaRoNiS","*.Tesla","*.Tfudeq","*.TheTrumpLockerf","*.TheTrumpLockerp","*.Tiger4444","*.Timestamp","*.Tor+","*.Tornado","*.TraNs","*.UIK1J","*.UIWIX","*.UKCZA","*.UNIT09","*.UNLIS","*.UselessFiles","*.VBRANSOM","*.VENDETTA","*.VIRUS","*.VIVAL","*.Vapor","*.Venusf","*.VforVendetta","*.VisionCrypt","*.W0YR8","*.WAITING","*.WALAN","*.WALAN,","*.WAND","*.WAmarlocked","*.WCRYT","*.WHY","*.WHY…","*.WINDOWS","*.WORMCRYPT0R","*.WORMKILLER@INDIA.COM.XTBL","*.WRNY","*.WWW","*.Wana Decrypt0r Trojan-Syria Editi0n","*.Where_my_files.txt","*.Whereisyourfiles","*.Work","*.Wx7A6","*.XBTL","*.XERO","*.XRNT","*.XVNAW","*.XY6LR","*.XZZX","*.Xcri","*.XiaoBa","*.XiaoBa1","*.XiaoBa34","*.XmdXtazX","*.XmdXtazX.","*.YAYA","*.YDHM","*.YIAQDG","*.YOLO","*.YOU-ARE-FUCKED-BY-BALILUWARE-(CODED-BY-HEROPOINT)","*.YOUR_LAST_CHANCE","*.YTBL","*.YYTO","*.YYYYBJQOQDU","*.Yakes","*.Z81928819","*.ZABLOKOWANE","*.ZAYKA","*.ZINO","*.ZW","*.Zeropadypt","*.Zimbra","*.Zzzz","*.[1701222381@qq.com].ETH","*.[BRAINCRYPT@INDIA.COM].BRAINCRYPT","*.[BaYuCheng@yeah.net].china","*.[Bas_ket@aol.com].java","*.[Brazzers@aolonline.top].arena","*.[DonovanTudor@aol.com].bat","*.[Enigma1crypt@aol.com].ETH","*.[File-Help@India.Com].mails","*.[Filesreturn247@gmx.de].lock","*.[GOFMEN17@YA.RU],CRP","*.[GuardBTC@cock.li].java","*.[Hardcorr@protonmail.com].java","*.[Hardcorrr@protonmail.com].java","*.[ID-][].JSWRM","*.[ID62133703]","*.[ID=*2uJ][Mail=letitbedecryptedzi@gmail.com].Lazarus","*.[ID=*][Mail=unlockme123@protonmail.com].Lazar","*.[ID]*[ID]","*.[ID]*[ID]Look","*.[Kromber@tutanota.com]","*.[MAXVISION@SECMAIL.PRO].CRIPTOGRAFADO","*.[MailPayment@decoder.com].ETH","*.[NO.TORP3DA@PROTONMAIL.CH].WALLET","*.[PINGY@INDIA.COM]","*.[SHIELD0@USA.COM].*.WALLET","*.[SSSDKVNSDFITD]","*.[Sepsis@protonmail.com].SEPSIS","*.[Traher@Dr.Com]","*.[Unlock24@cock.li].combo","*.[XAVAX@PM.ME].omerta","*.[absonkaine@aol.com].phoenix","*.[actum_signum@aol.com].onion","*.[admin@hoist.desi].*.WALLET","*.[adobe-123@tutanota.com].ETH","*.[amagnus@india.com].wallet","*.[amber777king@cock.li].amber","*.[assistance@firemail.cc].nuclear","*.[avalona.toga@aol.com].blocking","*.[avflantuheems1984@aol.com].adobe","*.[backdata@cock.li].CreamPie","*.[backtonormal@foxmail.com].adobe","*.[bacon@oddwallps.com].java","*.[batmanbitka1@cock.li].arena","*.[bitcharity@protonmail.com].com","*.[black.world@tuta.io].nuclear","*.[blellockr@godzym.me].bkc","*.[blind@cock.li].blind","*.[btc2018@tutanota.de].meduza","*.[btc@fros.cc].btc","*.[btccrypthelp@cock.li].ETH","*.[buy-decryptor@pm.me]","*.[china-decryptor@pm.me]","*.[cho.dambler@yandex.com]","*.[cockroach@cock.lu].COCKROACH","*.[costelloh@aol.com].phoenix","*.[crab7765@gmx.de].crab","*.[crypt1style@aol.com].MERS","*.[crypted_files@qq.com].aqva","*.[crypto7892@gmx.de].crypto","*.[crysis@life.com].*.WALLET","*.[cyberwars@qq.com].war","*.[daves.smith@aol.com]","*.[decodingfiles@tuta.io].java","*.[decrypthelp@qq.com].java","*.[decrypthelper@protonmail.com].phobos","*.[decryptmyfiles@qq.com].ETH","*.[decryptprof@qq.com].ETH","*.[drwho888@mail.fr].888","*.[dsupport@protonmail.com]","*.[eV3rbe@rape.lol].eV3rbe","*.[embrace@airmail.cc].embrace","*.[epta.mcold@gmail.com]","*.[epta.mcold@gmail.com],","*.[everbe@airmail.cc].everbe","*.[everest@airmail.cc].EVEREST","*.[evil@cock.lu].EVIL","*.[fileslocker@pm.me]","*.[firmabilgileri@bk.ru]","*.[frazeketcham@cnidia.com].eth.hv88g2","*.[grethen@tuta.io]","*.[gustafkeach@johnpino.com].ad","*.[help24decrypt@cock.li","*.[help24decrypt@cock.li]","*.[helpfilerestore@india.com].ETH","*.[insane@airmail.cc].insane","*.[lockhelp@qq.com].gate","*.[maxicrypt@cock.li].maxicrypt","*.[mercarinotitia@qq.com].adobe","*.[mich78@usa.com]","*.[mixon.constantine@aol.com].gamma","*.[mr.yoba@aol.com].yoba","*.[mrbin775@gmx.de].bin","*.[mrpeterson@cock.li].GFS","*.[notopen@countermail.com].NOT_OPEN","*.[oron@india.com].dharma","*.[pain@cock.lu].pain","*.[pain@onefinedstay.com].java","*.[papillon9275]","*.[paradisecity@cock.li].arena","*.[parambingobam@cock.li].adobe","*.[patern32@protonmail.com].omerta","*.[paydecryption@qq.com].brrr","*.[payransom@qq.com].adobe","*.[plombiren@hotmail.com].plomb","*.[ponce.lorena@aol.com]","*.[randal_inman@aol.com].help","*.[rans0me@protonmail.com].b00m","*.[raphaeldupon@aol.com].ETH","*.[resque@plague.desi].scarab","*.[restorehelp@qq.com].java","*.[satan2018@protonmail.com].java","*.[skeleton@rape.lol].skeleton","*.[slaker@india.com]*.wallet","*.[staRcRypt@tutanota.com].omerta","*.[stopencrypt@qq.com].adobe","*.[stopstorage@qq.com].java","*.[supp01@arimail.cc].napoleon","*.[suupport@protonmail.com].scarab","*.[teroda@bigmir.net].masterteroda@bigmir.net","*.[thedecrypt111@qq.com].ETH","*.[thunderhelp@airmail.cc].thunder","*.[ti_kozel@lashbania.tv].костя","*.[velasquez.joeli@aol.com]","*.[volcano666@tutanota.de].volcano","*.[w_decrypt24@qq.com].zq","*.[w_unblock24@qq.com].ws","*.[welesmatron@aol.com].btc","*.[writehere@qq.com].btc","*.[yoursalvations@protonmail.ch].neverdies@tutanota.com","*.[zoro4747@gmx.de].zoro","*._AiraCropEncrypted!","*._Crypted","*._NEMTY*","*._NEMTY_*_","*._NEMTY_BTKid9H_","*.__dilmaV1","*._raphaeldupon@aol.com_.btc","*._ryp","*.a19","*.a5zfn","*.a800","*.a990","*.aRpt","*.aa1","*.aaa","*.aajf","*.abc","*.abcd","*.acc","*.actin","*.actor","*.acuna","*.acute","*.adage","*.adam","*.adapaterson@mail.com.mkmk","*.adk","*.adobe","*.adobee","*.aes!","*.aes128ctr","*.aes_ni","*.aes_ni_0day","*.aescrypt","*.aesir","*.aga","*.airacropencrypted!","*.akaibvn","*.akira","*.alanwalkergod@protonmail.com","*.albertkerr94@mail.com.m5m5","*.aleta","*.alien","*.alilibat","*.allcry","*.alosia","*.altdelete@cock.li.district","*.am","*.amba","*.amber","*.amnesia","*.anami","*.andonio","*.android","*.andymarvin","*.angelamerkel","*.animus","*.anon","*.anonimus.mr@yahoo.com","*.anonymous","*.antihacker2017","*.anubi","*.ap19","*.aqva","*.area","*.arena","*.areyoulovemyrans","*.armadilo1","*.arrow","*.artilkilin@tuta.io.wq2k","*.asasin","*.asdasdasd","*.au1crypt","*.auw2w2g0","*.axx","*.azero","*.b00m","*.b0ff","*.b29","*.b5c6","*.b78vi7v6ri66b","*.b89b","*.bRcrypT","*.backup","*.badday","*.badutclowns","*.bagi","*.bam!","*.bananaCrypt","*.banjo","*.banta","*.bart","*.bart.zip","*.basilisque@protonmail_com","*.basslock","*.bbqb","*.beef","*.beep","*.beer","*.beets!Ransom","*.berost","*.berosuce","*.besub","*.betta","*.better_call_saul","*.bgCIb","*.bgtx","*.bguu","*.billingsupp","*.bip","*.birbb","*.bit","*.bitkangoroo","*.bitstak","*.biz","*.bizer","*.bk666","*.bkc","*.bkp","*.black007","*.blackruby","*.blank","*.bleep","*.bleepYourFiles","*.blind","*.blind2","*.bliun","*.bloc","*.blocatto","*.bloccato","*.block","*.block_file12","*.blocked","*.bloked","*.blower","*.bmn63","*.bmps@tutanota.com.major","*.bobelectron","*.bomber","*.booknish","*.boooam@cock_li","*.boost","*.bopador","*.bora","*.boris","*.boroff","*.boston","*.bot","*.bot!","*.braincrypt","*.breaking bad","*.breaking_bad","*.breakingbad","*.breeding123","*.brickr","*.bript","*.browec","*.brrr","*.brusaf","*.btc","*.btc -help-you","*.btc-help-you","*.btc.kkk.fun.gws","*.btcbtcbtc","*.btchelp@xmpp.jp","*.btcware","*.btix","*.budak","*.bufas","*.bunny","*.burn","*.bvjznsjlo","*.bwall","*.c300","*.cRh8","*.calix","*.cammora","*.canihelpyou","*.cap","*.carcn","*.carote","*.cassetto","*.cawwcca","*.cbf","*.cbs0z","*.cbu1","*.ccc","*.cccmn","*.ccryptor","*.cdrpt","*.cekisan","*.cerber","*.cerber2","*.cerber3","*.cerber6","*.cesar","*.cetori","*.cezar","*.cezor","*.cfk","*.cfm","*.charck","*.charcl","*.charm","*.charmant","*.chch","*.chech","*.checkdiskenced","*.cheetah","*.chekyshka","*.chifrator@qq_com","*.choda","*.ciphered","*.cizer","*.ckey(RandomID).email(data1992@protonmail.com).pack14","*.ckey(oK5WFfTq).email(data1992@protonmail.com).pack14","*.clean","*.clf","*.clinTON","*.cloud","*.cmb","*.cmsnwned","*.cnc","*.cobain","*.cobra","*.cock.email","*.cock.li","*.cockista","*.code","*.coded","*.coder007@protonmail.com","*.codnat","*.codnat1","*.codnet","*.codnet1","*.codyprince92@mail.com.ovgm","*.coharos","*.coin","*.colecyrus@mail.com.b007","*.com2","*.combo","*.comrade","*.condat","*.contact-me-here-for-the-key-admin@adsoleware.com","*.coot","*.corrupted","*.cosakos","*.country82000","*.coverton","*.cr020801","*.cr1","*.crabs","*.craftul","*.crash","*.crashed","*.crazy","*.creeper","*.crime","*.crinf","*.cripted","*.criptiko","*.criptokod","*.cripton","*.cripttt","*.crjocker","*.crjoker","*.croc","*.crptd","*.crptrgr","*.cry","*.crybrazil","*.crying","*.cryp1","*.crypt","*.crypt1","*.crypt12","*.crypt2019","*.crypt38","*.crypt888","*.crypte","*.crypted","*.crypted!Sample","*.crypted034","*.crypted_bizarrio@pay4me_in","*.crypted_file","*.crypted_marztoneb@tutanota_de","*.crypted_pony_test_build*","*.crypted_pony_test_build_xxx_xxx_xxx_xxx_xxx","*.cryptes","*.cryptfile","*.cryptgh0st","*.crypto","*.cryptoNar","*.cryptoid","*.cryptojoker","*.cryptolocker","*.cryptotorlocker*","*.cryptowall","*.cryptowin","*.crypttt","*.cryptx*","*.cryptz","*.crypz","*.cs16","*.cspider","*.ctbl","*.ctrlalt@cock.li.district","*.cube","*.cxk_nmsl","*.cxkdata","*.cyberdrill","*.cypher","*.czvxce","*.d3g1d5","*.d4nk","*.dCrypt","*.da_vinci_code","*.dalle","*.damage","*.damoclis","*.danger","*.daris","*.darkness","*.darus","*.datun","*.david","*.davilarita@mail.com.yyy0","*.dbger","*.dcom","*.dcry","*.ddos","*.ddpcbi","*.deal","*.decodeme666@tutanota_com","*.decodeme666tutanota_com","*.decrypme","*.decrypt2017","*.decrypter@tutanota.com","*.decryptgarranty","*.decryptional","*.ded","*.dedo","*.deep","*.defender","*.demonslay335_you_cannot_decrypt_me!","*.deria","*.derp","*.desu","*.dfjhsalfhsakljfhsljkahfdjklashfdjklh","*.dharma","*.dian","*.die","*.digiworldhack@tutanota.com","*.diller13","*.disposed2017","*.divine","*.djuvq","*.djvup","*.djvuq","*.djvur","*.djvus","*.djvut","*.dlenggrl","*.dmo","*.dodger","*.dodoc","*.dolphin","*.dom","*.domino","*.domn","*.donation1@protonmail.ch.12345","*.donut","*.doomed","*.doples","*.dotmap","*.doubleoffset","*.dqb","*.dragnea","*.drume","*.drweb","*.ducueyuav","*.duhust","*.dutan","*.dviide","*.dwbiwty","*.dxjay","*.dxxd","*.dy8wud","*.dyaaghemy","*.dyatel@qq_com","*.e4m","*.eQTz","*.eTeRnItY","*.ebay","*.ecc","*.eclr","*.eddldzor","*.edgel","*.eky","*.elpvd","*.embrace","*.emilysupp","*.emsisosisoft","*.enc","*.enc_robbinhood","*.encedRSA","*.encencenc","*.encmywork","*.encoderpass","*.encrptd","*.encrypt","*.encryptd","*.encrypted.locked","*.encryptedAES","*.encryptedALL","*.encryptedRSA","*.encrypted[Payfordecrypt@protonmail.com]","*.encrypted_backup","*.encryptedped","*.encryptedyourfiles","*.enigma","*.enjey","*.eoeo","*.epic","*.etols","*.euclid","*.evil","*.evillock","*.evolution","*.evopro","*.ex_parvis@aol.com.AIR","*.excuses","*.executioner","*.exotic","*.exploit","*.explorer","*.extension.srpx","*.exx","*.ezz","*.ezzyl","*.f*cked","*.fairytail","*.fake","*.fantom","*.fartplz","*.fast","*.fastrecovery.xmpp.jp","*.fastrecovery@airmail.cc","*.fastsupport@xmpp.jp","*.fat32","*.fbuvkngy","*.fedasot","*.ferosas","*.file0locked","*.filegofprencrp","*.fileiscryptedhard","*.filesfucked","*.filock","*.fire","*.firecrypt","*.firmabilgileri","*.fix","*.flat","*.flyper","*.fmoon","*.forasom","*.fordan","*.format","*.fox","*.freefoam","*.frend","*.frmvrlr2017","*.frtrss","*.fsdfsdfsdfsdfsdfsfdsfs","*.fuXcF","*.fuchsia","*.fuck","*.fuck_you_av_we_are_not_globe_fake","*.fucked","*.fucku","*.fuckyourdata","*.fun","*.g0h8iwj","*.g^od","*.game","*.gamma","*.gangbang","*.gankLocked","*.garcewa","*.garrantydecrypt","*.gate","*.gdb","*.ge010gic","*.ge0l0gic","*.ge0l0gic_readme.txt","*.gefickt","*.gehad","*.gembok","*.geno","*.gerber5","*.gero","*.gerosan","*.gesd","*.ghost","*.gigahertz","*.globe","*.gocr","*.godes","*.godra","*.goforhelp","*.gommemode","*.good","*.gore","*.gotcha","*.gr3g","*.granny","*.greystars@protonmail.com","*.grod","*.gropas","*.group","*.grovas","*.grovat","*.grt","*.grupothermot3k","*.grux","*.gruzin@qq_com","*.gryphon","*.guarded","*.guesswho","*.gui","*.gusau","*.guvara","*.gws","*.gws.porno","*.gоod","*.h3ll","*.hNcrypt","*.ha3","*.hac","*.hackdoor","*.hacked","*.hacked.by.Snaiparul","*.haka","*.hannah","*.happenencedfiles","*.happy","*.happydayzz","*.happyness","*.harma","*.hasp","*.haters","*.hb15","*.hccapx","*.hceem","*.hcked","*.hdeaf","*.hdmr","*.heets","*.heisenberg","*.help.Ransom","*.help24decrypt@qq.com","*.help_restore*.*","*.helpdecrypt@india.com","*.helpdecrypt@ukr*.net","*.helpdecrypt@ukr.net","*.helpdecrypt@ukr_net","*.helpmeencedfiles","*.helppme@india.com.*","*.herad","*.herbst","*.hermes837","*.heroset","*.hese","*.hets","*.hilegofprencrp","*.hitler","*.hjgdl","*.hncdumn","*.hnumkhotep","*.hnumkhotep@india.com.hnumkhotep","*.hnyear","*.hofos","*.honor","*.horon","*.horsuke@nuke.africa","*.how_to_recover*.*","*.howcanihelpusir","*.hrosas","*.htrs","*.hush","*.hydracrypt_ID*","*.hydracrypt_ID_*","*.iGotYou","*.iaufhhhfiles_BACK_PLS_READ.html","*.iaufhhhhfiles_BACK_PLS_READ.html","*.iaufkakfhsaraf","*.id-*.[*@*].*","*.id-*.[3442516480@qq.com].pdf","*.id-*.[Harmahelp73@gmx.de].harma","*.id-*.[MerlinWebster@aol.com].harma","*.id-*.[adm15@pr…","*.id-*.[admin@fentex.net].money","*.id-*.[admin@sectex.net].bot","*.id-*.[admin@spacedatas.com].ROGER","*.id-*.[asdbtc@aol.com].asd","*.id-*.[backdata.company@aol.com].ROGER","*.id-*.[backdatacompany@aol.com].html","*.id-*.[bitcoin1@foxmail.com].harma","*.id-*.[bitlocker@foxmail.com","*.id-*.[btcdecoding@qq.com].dqb","*.id-*.[karlosdecrypt@outlook.com].KARLS","*.id-*.[moncler@tutamail.com].redrum","*.id-*.[mr.hacker@tutanota.com].USA","*.id-*.[partfile@airmail.cc].com","*.id-*.[payday@tfwno.gf].html","*.id-*.[teammarcy10@cock.li].kharma","*.id-*.[veracrypt@foxmail.com].adobe","*.id-*.[vip76@protonmail.com].html","*.id-*.cmb","*.id-*6.[3442516480@qq.com].pdf","*.id-*E6.[3442516480@qq.com].pdf","*.id-.[clifieb@tutanota.com].nvram","*.id-.[hmdjam@protonmail.com].harma","*.id-.[hobbsadelaide@aol.com].harma","*.id-02B52D6C.[Bas_ket@aol.com].java","*.id-3044989498_x3m","*.id-502F1F51.[mstr.hacker@protonmail.com].KICK","*.id-C4BA3647.[fox5sec@aol.com].cmd","*.id.*.crazy","*.id[********-1161].[member987@tutanota.com].actin","*.id[*-*].[butters.felicio@aol.com].deal","*.id[*-*].[lockhelp@qq.com].acute","*.id[*-*].[wewillhelpyou@qq.com].adage","*.id[*-1075].[lewisswaffield.a@aol.com].help","*.id[*-1135].[walletwix@aol.com].actin","*.id[*-1161].[member987@tutanota.com].actin","*.id[*-2242].[Ke…","*.id[*-2252].[eccentric_inventor@aol.com].adage","*.id[*-2266].[decryptbox@airmail.cc].Adair","*.id[*-2275","*.id[*-2275].[checkcheck07@qq.com].Adame","*.id[*-2275].[raynorzlol@tutanota.com].Adame","*.id[*-2275].[recovermyfiles2019@thesecure.biz].Adame","*.id[*-2275].[supportcrypt2019@cock…","*.id[*-2299].[britt.looper@aol.com].phoenix","*.id[*-2300].[crysall.g@aol.com].banjo","*.id[*-2315].[decrypt@files.mn].Banks","*.id[*-2325].[zax4444@qq.com].Banta","*.id[*-2345].[recoverdata@cock.li].Banta","*.id[*-2387].[gruzudo@cock.li].Barak","*.id[*-2394].[adagekeys@qq.com].Caleb","*.id[*-2416].[restorebackup@qq.com].Caley","*.id[*-2423].[hanesworth.fabian@aol.com].dealemail","*.id[*-2425].[*n*@cock.li].Caley","*.id[*-2465].[keysfordecryption@airmail.cc].Calum","*.id[*-2495].[agent5305@firemail.cc].age","*.id[*-2497].[octopusdoc@mail.ee].octopus","*.id[*-2542].[bexonvelia@aol.com].Dever","*.id[*].[backcompanyfiles@protonmail.com].Calum","*.id[6AB8ABF5-2346].[limboshuran@cock].banta","*.id[C4BA3647-2250].[wewillhelpyou@qq.com].adage","*.id[C4BA3647-2271].[worldofdonkeys@protonmail.com].BORISHORSE","*.id[C4BA3647-2299].[britt.looper@aol.com].phoenix","*.id[C4BA3647-2301].[hanesworth.fabian@aol.com].banjo","*.id[RandomIP].[bron_lynn@aol.com].help","*.id_*********_.WECANHELP","*.id_*_.YOUR_LAST_CHANCE!","*.ifuckedyou","*.igza4c","*.ihsdj","*.iloveworld","*.impect","*.improved","*.imsorry","*.incpas","*.infected","*.infileshop@gmail_com_ID44","*.info","*.info@mymail9[dot]com","*.info@sharebyy[dot]com","*.infovip@airmail.cc","*.insane","*.insta","*.invaded","*.ipygh","*.ironhead","*.isis","*.isolated","*.ispfv","*.israbye","*.iudgkwv","*.iwanthelpuuu","*.jack","*.jaff","*.jamper","*.jbptlio","*.jc","*.jcry","*.jeepdayz@india.com","*.jes","*.jewsomware","*.jey","*.jimm","*.jodis","*.josep","*.jse","*.jsworm","*.jundmd@cock.li*","*.jungle@anonymousspechcom","*.junior","*.junked","*.jupstb","*.justbtcwillhelpyou","*.justice","*.jzphmsfs","*.k0stya","*.kali","*.karl","*.karne","*.katipuneros","*.katyusha","*.kci0n","*.kcwenc","*.ke3q","*.kee","*.keepcalm","*.kencf","*.kernel_complete","*.kernel_pid","*.kernel_time","*.kes$","*.keybtc@inbox","*.keybtc@inbox_com","*.kezoz","*.kgpvwnr","*.kilit","*.kill","*.killedXXX","*.kimchenyn","*.kimcilware","*.kimcilware.locked","*.king_ouroboros*","*.kirked","*.kiss","*.kitty","*.kjh","*.kkk","*.klope","*.kodg","*.kok","*.korea","*.koreaGame","*.korrektor","*.kostya","*.kovasoh","*.kr","*.kr3","*.kraken","*.kratos","*.kraussmfz","*.kropun","*.kroput","*.kroput1","*.krusop","*.krypted","*.kryptonite","*.krzffw","*.ktuhzxpi","*.kuntzware","*.kuub","*.kvag","*.kvllyatprotonmaildotch","*.kwaaklocked","*.kyra","*.lalabitch","*.lalabitch,","*.lambda.l0cked","*.lambda_l0cked","*.lamo","*.langolier","*.lanset","*.lapoi","*.lbiaf6c8","*.lbkut","*.lcked","*.lcphr","*.lcphr!Ransom","*.leen","*.leenapidx","*.leenapidx@snakebite.com.hrhr","*.legacy","*.legion","*.leon","*.les#","*.lesli","*.letmetrydecfiles","*.leto","*.lfk","*.lfv77az","*.libbywovas@dr.com.gr3g","*.like","*.lilocked","*.limbo","*.lime","*.litar","*.litra","*.litra!Sample","*.lock93","*.lockd","*.locked","*.locked-*","*.locked.zip","*.locked3","*.locked_by_mR_Anonymous(TZ_HACKERS)","*.lockedfile","*.lockedgood","*.locker","*.lockhelp@qq.gate","*.locklock","*.lockme","*.locky","*.lockymap","*.lokas","*.lokf","*.lokitus","*.lol","*.lolita","*.londec","*.loptr","*.lordofshadow","*.lost","*.lotej","*.lotep","*.loveransisgood","*.lovewindows","*.loveyouisreal","*.luboversova148","*.luceq","*.luces","*.lucky","*.lukitus","*.lukitus-tiedostopäätettä","*.lurk","*.m3g4c0rtx","*.m3ga","*.m3ga*","*.m3gac0rtx","*.madebyadam","*.madek","*.madekv120","*.mafee","*.magic","*.magic_software_syndicate","*.mailto[2Hamlampampom@cock.li].82a80","*.major","*.makkonahi","*.maktub","*.malwarehunterteam","*.mamasitaq","*.mamba","*.mammon","*.maniac","*.mapo","*.mariacbc","*.mars","*.masked","*.masodas","*.masok","*.master","*.maxicrypt","*.maysomware","*.mbed","*.mbrcodes","*.mdk4y","*.mecury","*.medal","*.medsv162","*.megac0rtx","*.megacortex","*.meka","*.mention9823","*.merl","*.mers","*.messenger-*","*.metan","*.mich","*.micro","*.middleman2020","*.mike","*.mind","*.mo7n","*.mockba","*.mogera","*.mogranos","*.moka","*.moments2900","*.money","*.monro","*.mordor","*.moresa","*.mosk","*.mouse","*.ms13","*.msj","*.msop","*.mtk118","*.mtogas","*.muhstik","*.muslat","*.mvp","*.myjob","*.myransext2017","*.myskle","*.n3xtpharma","*.n7ys81w","*.nWcrypt","*.nacro","*.nakw","*.nalog@qq_com","*.napoleon","*.nasoh","*.nazcrypt","*.nbes","*.ndarod","*.ndpyhss","*.needdecrypt","*.needkeys","*.neitrino","*.nelasod","*.nemesis","*.nemo-hacks.at.sigaint.org","*.nemty","*.neras","*.nesa","*.netn6","*.newlock","*.news","*.nhHtFWV","*.ninja","*.no_more_ransom","*.no_more_ransomware","*.noblis","*.nochance","*.nols","*.non","*.noos","*.nopasaran","*.noproblemwedecfiles","*.norvas","*.nosafe","*.nostro","*.notfoundrans","*.novasof","*.nozelesn","*.nsmf","*.ntu","*.ntuseg","*.nuclear","*.nuclear55","*.nuke55","*.nuksus","*.nusar","*.nvetud","*.nvram","*.nytom","*.o$l","*.obagarmrk","*.obfuscated","*.ocean","*.octopus","*.odcodc","*.odin","*.odveta","*.ogre","*.okean*","*.okokokokok","*.olduw","*.oled","*.omerta","*.omnisphere","*.one","*.one-we_can-help_you","*.oneway","*.oni","*.online24files@airmail.cc","*.onlinesupport","*.only-we_can-help_you","*.onx","*.onyon","*.oops","*.oor","*.open_readme.txt.ke3q","*.openforyou@india.com","*.oplata@qq_com","*.orion","*.oshit","*.osiris","*.osk","*.oslawcmme","*.otherinformation","*.owned","*.p3d374","*.p5tkjw","*.pablukCRYPT","*.pabluklocker","*.pack14","*.padcrypt","*.parad1gm","*.parrot","*.partially.cryptoNar","*.partially.cryptojoker","*.pay2me","*.paybtcs","*.paycoin","*.paycyka","*.payfordecrypt","*.payfornature@india.com.crypted","*.payforunlock","*.paym","*.paymds","*.paymrss","*.paymrts","*.payms","*.paymst","*.paymts","*.payransom","*.payrms","*.pays","*.paytounlock","*.pdcr","*.pdf.p3rf0rmr","*.pdf_Axffyq_{babyfromparadise666@gmail.com}.p3rf0rm4","*.pdff","*.pedro","*.peet","*.pennywise","*.peosajwqfk","*.peta","*.petra","*.pfanz","*.phantom","*.phoenix","*.pidom","*.pidon","*.piny","*.pizda@qq_com","*.pizdec","*.pizdosik","*.pky","*.plauge17","*.pleaseCallQQ","*.pluto","*.pnr","*.poof","*.poolezoor","*.poop","*.popotic","*.popoticus","*.porno","*.porno.pornoransom","*.pornoransom","*.potato","*.powerfuldecrypt","*.powerfulldecrypt","*.powned","*.poyvonm","*.ppam","*.pr0tect","*.predator","*.proced","*.proden","*.promock","*.promoks","*.promorad","*.promorad2","*.promos","*.promoz","*.prosperous666","*.prus","*.pscrypt","*.psh","*.pulsar1","*.pumas","*.purge","*.pwned","*.pysa","*.pzdc","*.qbix","*.qbtex","*.qnbqw","*.qq_com*","*.qwerty","*.qweuirtksd","*.qwex","*.qwqd","*.r3store","*.radman","*.raid10","*.raldge","*.raldug","*.ram","*.ramen","*.rand","*.ranranranran","*.ranrans","*.ransomcrypt","*.ransomed@india.com","*.ransomwared","*.rapid","*.rat","*.razarac","*.razy","*.razy1337","*.rcrypted","*.rdmk","*.reaGAN","*.read_to_txt_file.yyto","*.readme_txt","*.realfs0ciety*","*.realfs0ciety@sigaint.org.fs0ciety","*.recme","*.reco","*.recovery_email_[retmydata@protonmail.com]*.aes256","*.recovery_email__retmydata@protonmail.com__*_.aes256.testE","*.recry1","*.rectot","*.redl","*.redmat","*.redrum","*.refols","*.rekt","*.relock@qq_com","*.remind","*.rencrypted","*.rent","*.restore_fi*.*","*.resurrection","*.revolution","*.reycarnasi1983@protonmail.com.gw3w","*.rezuc","*.righ","*.rip","*.risk","*.rjzR8","*.rnsmwr","*.rnsmwre","*.robbinhood","*.robinhood","*.rokku","*.roland","*.roldat","*.rontok","*.rose","*.rpd","*.rsalive","*.rsucozxze","*.rtyrtyrty","*.rumba","*.rumblegoodboy","*.ryk","*.ryp","*.ryx","*.s1crypt","*.sVn","*.safe","*.sage","*.sambo","*.sambo,","*.same","*.sanction","*.sanders4!","*.sapphire","*.sarut","*.satan","*.saturn","*.scarab","*.scl","*.scorpio","*.scrcrw","*.sdk","*.sdwwbrb","*.sea","*.secure","*.securityP","*.seed","*.serpent","*.setimichas1971@protonmail.com.b4wq","*.sexy","*.sfs","*.sgood","*.sguard","*.shade8","*.shadi","*.shadow","*.shariz","*.shelbyboom","*.shifr","*.shinigami","*.shino","*.shit","*.shutdown57","*.sifreli","*.sigrun","*.sinopal","*.sinta","*.si…","*.sjjpu","*.skunk","*.skvtb","*.sky","*.skymap","*.skynet","*.skype","*.slvpawned","*.snake","*.snake4444","*.snatch","*.son","*.sophos","*.sorry","*.sorryforthis","*.spaß","*.spectre","*.spider","*.spora","*.sport","*.spyhunter","*.sr0yz","*.ssananunak1987@protonmail.com.b2fr","*.sshxkej","*.ssimpotashka@gmail.com","*.stare","*.stevenseagal@airmail.cc","*.stn","*.stone","*.stroman","*.stun","*.styver","*.styx","*.suffer","*.sun","*.support@anonymous-service.cc.ppdddp?Unusual","*.supported2017","*.supportfiless24@protonmail.ch","*.suppose666","*.surprise","*.sux","*.sux.AES128","*.switch","*.symbiom_ransomware_locked","*.syrk","*.sysdown","*.szesnl","*.szf","*.tabufa","*.tanos","*.tastylock","*.tater","*.tax","*.technicy","*.tedcrypt","*.telebak","*.tfude","*.tfudet","*.tgmn","*.theva","*.theworldisyours","*.thor","*.thunder","*.tmp.exe","*.to.dernesatiko@mail.com.crypted","*.todar","*.todarius","*.toec","*.tokog","*.toxcrypt","*.trevinomason1@mail.com.vsunit","*.triple_m","*.tro","*.tron","*.tronas","*.trosak","*.troyancoder@qq_com","*.truke","*.trump","*.trun","*.try","*.tsv","*.ttt","*.tuki17@qq.com","*.tunca","*.twist","*.tzu","*.uDz2j8mv","*.ucftz*","*.udjvu","*.uk-dealer@sigaint.org","*.ukr.net*","*.ukrain","*.unavailable","*.unbrecrypt_ID_*","*.upd9ykc65v","*.usr0","*.uudjvu","*.vCrypt1","*.vaca","*.vally","*.vanss","*.vault","*.vdul","*.velikasrbija","*.velso","*.vendetta2","*.venusp","*.veracrypt","*.verasto","*.verschlüsselt","*.vesad","*.vesrato","*.via","*.viiper","*.viki","*.vindows","*.volcano","*.vpgvlkb","*.vrmrkz","*.vscrypt","*.vulston","*.vusad","*.vvv","*.vxLock","*.wal","*.wallet","*.wannacash","*.wannacryv2","*.warn_wallet","*.wasted","*.wav_list","*.wcry","*.wctc","*.wdie","*.weapologize","*.weareyourfriends","*.weencedufiles","*.werd","*.wewillhelp@airmail.cc","*.wflx","*.whatthefuck","*.whycry","*.wiki","*.wincry","*.windows10","*.wlu","*.wmfxdqz","*.wncry","*.wncrypt","*.wncryt","*.wndie","*.wnry","*.wooly","*.wowreadfordecry","*.wowreadfordecryp","*.wowwhereismyfiles","*.write","*.write_on_email","*.write_us_on_email","*.wsmile","*.wtdi","*.wtf","*.wuciwug","*.wvtr0","*.wxdrJbgSDa","*.wyvern","*.x0lzs3c","*.x1881","*.x3m","*.x3mpro","*.xcry7684","*.xcrypt","*.xdata","*.xfile","*.xhspythxn","*.xiaoba10","*.xiaoba11","*.xiaoba12","*.xiaoba13","*.xiaoba14","*.xiaoba15","*.xiaoba16","*.xiaoba17","*.xiaoba18","*.xiaoba19","*.xiaoba2","*.xiaoba20","*.xiaoba21","*.xiaoba22","*.xiaoba23","*.xiaoba24","*.xiaoba25","*.xiaoba26","*.xiaoba27","*.xiaoba28","*.xiaoba29","*.xiaoba3","*.xiaoba30","*.xiaoba31","*.xiaoba32","*.xiaoba33","*.xiaoba4","*.xiaoba5","*.xiaoba6","*.xiaoba7","*.xiaoba8","*.xiaoba9","*.xncrypt","*.xolzsec","*.xorist","*.xort","*.xoza","*.xrtn","*.xtbl","*.xuy","*.xwz","*.xxx","*.xxxxx","*.xyz","*.xz","*.yG","*.yarraq","*.yatron","*.ykcol","*.yl","*.yoewy","*.youransom","*.yourransom","*.yq75w627","*.yum","*.z3r0","*.zXz","*.zatrov","*.zbt","*.zc3791","*.zcrypt","*.zendr4","*.zeppelin","*.zepto","*.zilla","*.ziqzqzdi","*.zlpzdel","*.zobm","*.zoh","*.zorin","*.zoro","*.zorro","*.ztsysjz","*.zuzya","*.zycrypt","*.zyklon","*.zypto*","*.zzz","*.zzz12","*.zzzzz","*.zzzzzzzz","*.{25BF1879-A2DC-B66A-3CCC-XXXXXXXXXXXX}","*.{CALLMEGOAT@PROTONMAIL.COM}CMG","*.{CRYPTENDBLACKDC}","*.{Help557@gmx.de}.exe","*.{Killback@protonmail.com}KBK","*.{XXXXX-EFEE-6C04-D2DC-A9EFA812DD11}!","*.{XXXXXXX-588E-7D5B-AED1-2CD51808DE12}","*.{incredible0ansha@tuta.io}.ARA","*.{ljspqk7@aol.com}.BRT92","*.{mattpear@protonmail.com}","*.{mattpear@protonmail.com}MTP","*.{saruman7@india.com}.BRT92","*.~HL*","*.~xdata~","*.Защищено","*.инструкция по оплате.txt","*.кибер разветвитель","*.已加密","*.干物妹！","*.암호화됨","*0nl1ne*","*@*.blocking","*@LOCKED","*@adsoleware.com*","*@cock.email","*@cock.lu*","*@cumallover.me*","*@files.mn*","*@gmail_com_*","*@india.com*","*@sectex*net*","*@tfwno.gf*","*@tuta.io]","*@tutanota.com]","*ABAT*INFO*.*","*BlockBax*","*Decryptoroperator@qq.com","*ENCx45cR*","*EdgeLocker*.exe","*HERMES","*How to Decrypt Files-*.html","*Instraction*","*RANSOMED*","*RT4BLOCK","*ReadMe_Decryptor.txt","*SIMMYWARE*","*[Beamsell@qq.com].bip","*[RELOCK001@TUTA.IO]","*[cryptservice@inbox.ru]*","*[cryptsvc@mail.ru].*","*[decryptdata@qq.com].rar","*[files.restore@aol.com].write","*[gomer_simpson2@aol.com].phobos","*[ignatevv330@gmail.com].java","*[java2018@tuta io].arrow","*[lavandos@dr.com].wallet","*[p4d@tuta.io].com","*[qmqtt@protonmail.ch].HRM","*[qrrqtt@protonmail.ch].HRM","*[remarkpaul77@cock.li].JSWORM","*[shivamana@seznam.cz].pip","*].block","*_.rmd","*_HELP_instructions.html","*_HOWDO_text.bmp","*_HOWDO_text.html","*_READ_THIS_FILE_*_*","*_WHAT_is.html","*_[LINERSMIK@NAVER.COM][JINNYG@TUTANOTA","*__{}.VACv2","*_crypt","*_help_instruct*.*","*_luck","*_nullbyte*","*_recover_*.*","*_ryp","*_steaveiwalker@india.com_","*adobe.gefest","*aes_ni_gov","*bingo@opensourcemail.org","*cerber2","*decipher*","*decrypt my file*.*","*decrypt your file*.*","*decryptmyfiles*.*","*djvuu","*drakosho_new@aol.com*","*files_are_encrypted.*","*fuga139gh@dr.com*","*garryweber@protonmail.ch","*gmail*.crypt","*help_restore*.*","*how_to_recover*.*","*id-*.BI_ID","*id-*_[*@*.*].*","*id-.LyaS","*info@kraken.cc_worldcza@email.cz","*install_tor*.*","*keemail.me*","*king_ouroboros*","*lockhelp@qq.com","*maestro@pizzacrypts.info","*msptermthemes*","*opentoyou@india.com","*qibfmkeM5*","*qq_com*","*qweasd*","*rec0ver*.*","*recover_instruction*.*","*recover}-*.*","*restore_fi*.*","*snowpicnic*","*structsstructs*","*tflower*","*ukr.net*","*wall.i","*want your files back.*","*warning-!!*.*","*ymayka-email@yahoo.com.cryptotes","*zn2016","*{alexbanan@tuta.io}.CORP","---README---.TXT",". vesrato","..g.",".0x0",".1999",".1txt",".31392E30362E32303136_[*]_LSBJ1",".6vr378txi",".73i87A",".777",".7h9r",".8lock8",".AES256",".AFD",".Alcatraz",".AngleWare",".BarRax",".CCCRRRPPP",".CHIP",".CONTACTUS",".CRRRT",".CRYPTOSHIEL",".CRYPTOSHIELD",".CTB2",".CTBL",".CrySiS",".CryptoTorLocker2015!",".DALE",".DATASTOP",".DATAWAIT",".DHARMA",".DIABLO6",".Do_not_change_the_filename",".ENC",".ENCR",".ENCRYPTED",".ENCRYPTED_BY_LLTP",".ENCRYPTED_BY_LLTPp",".EnCiPhErEd",".EnCrYpTeD",".Encrypted",".FenixIloveyou!!",".FuckYourData",".H3LL",".HA3",".INFOWAIT",".KARLOS",".KEYH0LES",".KEYPASS",".KEYZ",".KRAB",".Kirked",".L0CKED",".L0cked",".LOL!",".LeChiffre",".Licked",".Locked",".Locked-by-Mafia",".MERRY",".MKJL",".MRCR1",".OMG!",".OMG*",".PAUSA",".PEGS1",".PLAUGE17",".PLUT",".PoAr2w",".PzZs",".R.i.P",".R16M01D05",".R4A",".R5A",".RAD",".RADAMANT",".RARE1",".RDM",".REVENGE",".RMCM1",".RRK",".RSNSlocked",".RSplited",".SAVEfiles",".STOP",".STOPDATA",".SUPERCRYPT",".SUSPENDED",".SecureCrypted",".Silent",".TheTrumpLockerf",".TheTrumpLockerfp",".VBRANSOM",".Venusf",".Venusp",".VforVendetta",".WAITING",".WCRY",".WHY",".WNCRY",".Where_my_files.txt",".Whereisyourfiles",".XRNT",".XTBL",".XXX",".Z81928819",".ZINO",".[*].blt",".[*].encrypted",".[*].globe",".[*].raid10",".[*]_luck",".[decryptor@cock.li].dcrtr",".[mia.kokers@aol.com]",".[ogorman.linoel@aol.com].help",".[ti_kozel@lashbania.tv].*","._AiraCropEncrypted",".__AiraCropEncrypted!",".___xratteamLucked",".a19",".aaa",".abc",".adk",".adobe",".adobee",".adr",".aes",".aesir",".aga",".amba",".angelamerkel",".antihacker2017",".ap19",".axx",".bart",".bart.zip",".berost",".besub",".better_call_saul",".bin",".bip",".bitstak",".bleep",".bleepYourFiles",".bloc",".blocatto",".blower",".boston",".braincrypt",".breaking_bad",".bript",".browec",".btc",".btc-help-you",".btcbtcbtc",".btcware",".bufas",".bxtyunh",".cbf",".ccc",".cerber",".cerber2",".cerber3",".cezor",".charck",".charcl",".chech",".chifrator@qq_com",".cifgksaffsfyghd",".clf",".code",".coded",".codnat",".codnat1",".comrade",".coverton",".cr1",".crashed",".crime",".crinf",".criptiko",".criptoko",".criptokod",".cripttt",".crjoker",".crptrgr",".crptxxx",".cry",".cry_",".cryp1",".crypt",".crypt*",".crypt38",".crypted",".crypted_file",".crypto",".cryptolocker",".crypttt",".cryptz*",".crypz",".css",".ctbl",".czvxce",".d4nk",".dCrypt",".da_vinci_code",".dalle",".damage",".darkness",".davda",".decrypt2017",".ded",".deria",".devil",".dglnl",".dharma",".disappeared",".djvu",".djvuq",".djvur",".djvus",".djvut",".djvuu",".domino",".doomed",".doples",".dotmap",".drume",".dutan",".dxxd",".dyatel@qq_com _ryp",".ecc",".edgel",".enc",".encedRSA",".encmywork",".encoderpass",".encrypt",".encrypted",".encryptedAES",".encryptedRSA",".encryptedyourfiles",".enigma",".epic",".eth",".etols",".evillock",".exotic",".exx",".ezz",".fantom",".fear",".fedasot",".ferosas",".file0locked",".fileiscryptedhard",".filock",".firecrypt",".forasom",".fordan",".frtrss",".fs0ciety",".fuck",".fucked",".fun",".gefickt",".gerosan",".good",".googl",".grovas",".grovat",".grt",".gruzin@qq_com",".guvara",".gws",".h3ll",".ha3",".hannah",".hb15",".helpdecrypt@ukr.net",".helpmeencedfiles",".herbst",".heroset",".hets",".hnumkhotep",".hofos",".horon",".hrosas",".html",".hush",".iaufkakfhsaraf",".id-*.[*@*].air",".id-*.cry",".id-*_help@decryptservice.info",".id-[*]-maestro@pizzacrypts.info",".id-_CarlosBoltehero@india.com_",".id-_garryweber@protonmail.ch",".id-_julia.crown@india.com_",".id-_locked",".id-_locked_by_krec",".id-_locked_by_perfect",".id-_maria.lopez1@india.com_",".id-_r9oj",".id-_steaveiwalker@india.com_",".id-_tom.cruz@india.com_",".id-_x3m",".iloveworld",".infected",".isis",".iwanthelpuuu",".jack",".justbtcwillhelpyou",".karma",".kencf",".keybtc@inbox_com",".killed*",".kimcilware",".kiratos",".kkk",".klope",".korrektor",".kostya",".kr3",".kraken",".kratos",".kropun",".kroput",".kroput1",".kuub",".lambda_l0cked",".lanset",".lesli",".letmetrydecfiles",".litar",".lock",".lock93",".locked",".locked-[*]",".locklock",".locky",".lokas",".lotep",".lovewindows",".luces",".lukitus",".madebyadam",".magic",".maktub",".megac0rtx",".micro",".mike!Ransom",".mogera",".mole",".mole02",".moresa",".muslat",".myskle",".nalog@qq_com",".nampohyu",".neitrino",".nemo-hacks.at.sigaint.org",".neras",".no_more_ransom",".nochance",".noproblemwedecfiles",".norvas",".notfoundrans",".nuclear55",".nusar",".odcodc",".odin",".ohwqg",".only-we_can-help_you",".oops",".openforyou@india.com",".oplata@qq_com",".oshit",".osiris",".otherinformation",".p5tkjw",".padcrypt",".paybtcs",".payms",".paymst",".payransom",".payrmts",".paytounlock",".pdff",".phobos",".pidon",".pizda@qq_com",".plomb",".poret",".porno",".potato",".powerfulldecrypt",".proden",".promock",".promok",".promoks",".promorad",".promorad2",".promos",".promoz",".protected",".pulsar1",".puma",".pumas",".pumax",".purge",".pzdc",".r5a",".radman",".raldug",".razy",".rdmk",".rectot",".redmat",".refols",".rekt",".relock@qq_com",".remind",".rescuers@india.com.3392cYAn548QZeUf.lock",".rezuc",".rip",".rmd",".rnsmwr",".rokku",".roland",".roldat",".rumba",".sage",".sanction",".sarut",".scarab",".scl",".serpent",".sexy",".shadow",".shino",".shit",".sifreli",".skymap",".sport",".stn",".stone",".surprise",".szf",".tfude",".tfudeq",".tfudet",".theworldisyours",".thor",".todarius",".toxcrypt",".tro",".tronas",".trosak",".troyancoder@qq_com",".truke",".trun",".ttt",".tzu",".udjvu",".uk-dealer@sigaint.org",".unavailable",".unlockvt@india.com",".uudjvu",".vault",".velikasrbija",".verasto",".versiegelt",".vindows",".vscrypt",".vvv",".vxLock",".wallet",".wcry",".weareyourfriends",".weencedufiles",".wflx",".windows10",".wncry",".wnx",".xcri",".xcrypt",".xort",".xrtn",".xtbl",".xxx",".xyz",".yourransom",".zXz",".zc3791",".zcrypt",".zepto",".zerofucks",".zorro",".zyklon",".zzz",".zzzzz",".{CRYPTENDBLACKDC}",".~",".~xdata~",".кибер разветвитель",".已加密","000-IF-YOU-WANT-DEC-FILES.html","000-No-PROBLEM-WE-DEC-FILES.html","000-PLEASE-READ-WE-HELP.html","0000-SORRY-FOR-FILES.html","001-READ-FOR-DECRYPT-FILES.html","005-DO-YOU-WANT-FILES.html","009-READ-FOR-DECCCC-FILESSS.html","027cc450ef5f8c5f653329641ec1fed9*.*","0_HELP_DECRYPT_FILES.HTM","170fb7438316.exe","4-14-2016-INFECTION.TXT","52036F92.tmp","686l0tek69-HOW-TO-DECRYPT.txt","@Please_Read_Me@.txt","@WARNING_FILES_ARE_ENCRYPTED.*.txt","@WanaDecryptor@.*","@_RESTORE-FILES_@.*","@_USE_TO_FIX_*.txt","@decrypt_your_files.txt","AArI.jpg","ASSISTANCE_IN_RECOVERY.txt","ATLAS_FILES.txt","ATTENTION!!!.txt","ATTENTION.url","About_Files.txt","Aescrypt.exe","AllFilesAreLocked*.bmp","BTC_DECRYPT_FILES.txt","BUYUNLOCKCODE","BUYUNLOCKCODE.txt","BitCryptorFileList.txt","Blooper.exe","C-email-*-*.odcodc","COME_RIPRISTINARE_I_FILE.*","COMO_ABRIR_ARQUIVOS.txt","COMO_RESTAURAR_ARCHIVOS.html","COMO_RESTAURAR_ARCHIVOS.txt","CRYPTOID_*","CallOfCthulhu.exe","ClopReadMe.txt","Coin.Locker.txt","Comment débloquer mes fichiers.txt","Como descriptografar seus arquivos.txt","CryptoRansomware.exe","Crytp0l0cker.Upack.dll","Crytp0l0cker.dll","Crytp0l0cker.exe","Cversions.2.db","Cyber SpLiTTer Vbs.exe","DALE_FILES.TXT","DECRYPT-FILES.html","DECRYPTION INSTRUCTIONS.txt","DECRYPTION.TXT","DECRYPTION_HOWTO.Notepad","DECRYPT_INFO.txt","DECRYPT_INFORMATION.html","DECRYPT_INSTRUCTION.HTML","DECRYPT_INSTRUCTION.TXT","DECRYPT_INSTRUCTION.URL","DECRYPT_INSTRUCTIONS.TXT","DECRYPT_INSTRUCTIONS.html","DECRYPT_ReadMe.TXT","DECRYPT_ReadMe1.TXT","DECRYPT_Readme.TXT.ReadMe","DECRYPT_YOUR_FILES.HTML","DECRYPT_YOUR_FILES.txt","DESIFROVANI_POKYNY.html","DOSYALARINIZA ULAŞMAK İÇİN AÇINIZ.html","Decoding help.hta","Decrypt All Files *.bmp","DecryptAllFiles*.txt","DecryptAllFiles.txt","DecryptFile.txt","Decryptyourdata@qq.com","DesktopOsiris.*","DesktopOsiris.htm","EMAIL_*_recipient.zip","ENCRYPTED.TXT","ENTSCHLUSSELN_HINWEISE.html","FACT. 8-9-1278104.doc","FA_HLEH3S83AO22WO.doc","FE04.tmp","FILES ENCRYPTED.txt","FILES.TXT","FILESAREGONE.TXT","FILES_BACK.txt","File Decrypt Help.html","File_Encryption_Notice.txt","Files encrypted.html","GJENOPPRETTING_AV_FILER.html","GJENOPPRETTING_AV_FILER.txt","GNNCRY_Readme.txt","Galaperidol.exe","GetYouFiles.txt","GoRansom.txt","HELLOTHERE.TXT","HELP-ME-ENCED-FILES.html","HELPDECRYPT.TXT","HELPDECYPRT_YOUR_FILES.HTML","HELP_BY_CROC.TXT","HELP_DECRYPT.HTML","HELP_DECRYPT.HTML*","HELP_DECRYPT.PNG","HELP_DECRYPT.URL","HELP_DECRYPT.lnk","HELP_ME_PLEASE.txt","HELP_RECOVER_FILES.txt","HELP_RESTORE_FILES.txt","HELP_RESTORE_FILES_*.*","HELP_RESTORE_FILES_*.TXT","HELP_TO_DECRYPT_YOUR_FILES.txt","HELP_TO_SAVE_FILES.bmp","HELP_TO_SAVE_FILES.txt","HELP_YOURFILES.HTML","HELP_YOUR_FILES.PNG","HELP_YOUR_FILES.TXT","HELP_YOUR_FILES.html","HILDACRYPTReadMe.html","HOW DECRIPT FILES.hta","HOW TO DECRYPT FILES.HTML","HOW TO DECRYPT FILES.txt","HOW TO DECRYPT[1T0tO].txt","HOW TO RECOVER ENCRYPTED FILES-infovip@airmail.cc.TXT","HOW TO RECOVER ENCRYPTED FILES.TXT","HOW-TO-DECRYPT-FILES.HTM","HOW-TO-DECRYPT-FILES.HTML","HOW-TO-RESTORE-FILES.txt","HOWTO_RECOVER_FILES_*.*","HOWTO_RECOVER_FILES_*.TXT","HOW_CAN_I_DECRYPT_MY_FILES.txt","HOW_DECRYPT.HTML","HOW_DECRYPT.TXT","HOW_DECRYPT.URL","HOW_DECRYPT_FILES#.html","HOW_OPEN_FILES.hta","HOW_RETURN_FILES.TXT","HOW_TO_DECRYPT.HTML","HOW_TO_DECRYPT.txt","HOW_TO_DECRYPT_FILES.TXT","HOW_TO_DECRYPT_FILES.html","HOW_TO_DECRYPT_MY_FILES.txt","HOW_TO_FIX_!.TXT","HOW_TO_RESTORE_FILES.html","HOW_TO_RESTORE_FILES.txt","HOW_TO_RESTORE_YOUR_DATA.html","HOW_TO_UNLOCK_FILES_README_*.txt","HUR_DEKRYPTERA_FILER.html","HUR_DEKRYPTERA_FILER.txt","HVORDAN_DU_GENDANNER_FILER.html","HVORDAN_DU_GENDANNER_FILER.txt","HWID Lock.exe","Hacked_Read_me_to_decrypt_files.html","Hello There! Fellow @kee User!.txt","Help Decrypt.html","Help_Decrypt.txt","How Decrypt My Files.lnk","How To Decode Files.hta","How To Restore Files.txt","How decrypt files.hta","How to decrypt LeChiffre files.html","How to decrypt your data.txt","How to decrypt your files.jpg","How to decrypt your files.txt","How to decrypt.txt","How to get data back.txt","How to restore files.hta","HowDecrypt.gif","HowDecrypt.txt","HowToBackFiles.txt","HowToDecryptIMPORTANT!.txt","How_Decrypt_Files.hta","How_Decrypt_My_Files","How_To_Recover_Files.txt","How_to_decrypt_your_files.jpg","How_to_restore_files.hta","HowtoRESTORE_FILES.txt","Howto_RESTORE_FILES.html","Howto_Restore_FILES.TXT","IAMREADYTOPAY.TXT","IF YOU WANT TO GET ALL YOUR FILES BACK, PLEASE READ THIS.TXT","IF_WANT_FILES_BACK_PLS_READ.html","IF_YOU_WANT_TO_GET_ALL_YOUR_FILES_BACK_PLEASE_READ_THIS.TXT","IHAVEYOURSECRET.KEY","IMPORTANT READ ME.txt","IMPORTANT.README","INSTALL_TOR.URL","INSTRUCCIONES.txt","INSTRUCCIONES_DESCIFRADO.TXT","INSTRUCCIONES_DESCIFRADO.html","INSTRUCTION RESTORE FILE.TXT","INSTRUCTIONS_DE_DECRYPTAGE.html","INSTRUCTION_FOR_HELPING_FILE_RECOVERY.txt","ISTRUZIONI_DECRITTAZIONE.html","Important!.txt","Important_Read_Me.txt","Info.hta","Instruction for file recovery.txt","Instructionaga.txt","Instructions with your files.txt","JSWORM-DECRYPT.hta","KryptoLocker_README.txt","LEER_INMEDIATAMENTE.txt","LEIA_ME.txt","Lock.","Locked.*","MENSAGEM.txt","MERRY_I_LOVE_YOU_BRUCE.hta","NEWS_INGiBiToR.txt","NFS-e*1025-7152.exe","NOTE;!!!-ODZYSKAJ-PLIKI-!!!.TXT","OKSOWATHAPPENDTOYOURFILES.TXT","OKU.TXT","ONTSLEUTELINGS_INSTRUCTIES.html","OSIRIS-*.*","OSIRIS-*.htm","OkuBeni.txt","PAYMENT-INSTRUCTIONS.TXT","PLEASE-READIT-IF_YOU-WANT.html","PadCrypt.exe","Paxynok.html","Payment_Advice.mht","Payment_Instructions.jpg","Perfect.sys","READ IF YOU WANT YOUR FILES BACK.html","READ ME ABOUT DECRYPTION.txt","READ ME FOR DECRYPT.txt","READ TO UNLOCK FILES.salsa.*.html","READ-READ-READ.html","READ@My.txt","README HOW TO DECRYPT YOUR FILES.HTML","README!!!.txt","README-NOW.txt","README_DECRYPT_HYDRA_ID_*.txt","README_DECRYPT_HYRDA_ID_*.txt","README_DECRYPT_UMBRE_ID_*.jpg","README_DECRYPT_UMBRE_ID_*.txt","README_FOR_DECRYPT.txt","README_HOW_TO_UNLOCK.HTML","README_HOW_TO_UNLOCK.TXT","README_LOCKED.txt","README_RECOVER_FILES_*.html","README_RECOVER_FILES_*.png","README_RECOVER_FILES_*.txt","README_TO_RECURE_YOUR_FILES.txt","READTHISNOW!!!.TXT","READ_DECRYPT_FILES.txt","READ_IT.txt","READ_IT_FOR_GET_YOUR_FILE.txt","READ_ME.cube","READ_ME.html","READ_ME.mars","READ_ME_!.txt","READ_ME_ASAP.txt","READ_ME_FOR_DECRYPT_*.txt","READ_ME_HELP.png","READ_ME_HELP.txt","READ_ME_TO_DECRYPT_YOU_INFORMA.jjj","READ_THIS_FILE_1.TXT","READ_THIS_TO_DECRYPT.html","READ_TO_DECRYPT.html","READ__IT.txt","RECOVER-FILES.html","RECOVERY_FILE*.txt","RECOVERY_FILES.txt","RESTORE-.-FILES.txt","RESTORE-12345-FILES.TXT","RESTORE-SIGRUN.*","RESTORE_CORUPTED_FILES.HTML","RESTORE_FILES.HTML","RESTORE_FILES_*.*","RESTORE_FILES_*.txt","RESTORE_HCEEM_DATA.txt","RESTORE_INFO-*.txt","Rans0m_N0te_Read_ME.txt","Ransom.rtf","Read Me (How Decrypt) !!!!.txt","Read me for help thanks.txt","Read.txt","ReadDecryptFilesHere.txt","ReadME-Prodecryptor@gmail.com.txt","ReadME_Decrypt_Help_*.html","ReadMe_Decryptor.txt","ReadMe_Important.txt","Read_this_file.txt","Readme-Matrix.rtf","Readme_Restore_Files.txt","Receipt.exe","Recovery+*.html","Recovery+*.txt","Recupere seus arquivos aqui.txt","Restore Files.TxT","Restore_ICPICP_Files.txt","Restore_maysomware_files.html","Restore_your_files.txt","Runsome.exe","SECRET.KEY","SECRETIDHERE.KEY","SECURITY-ISSUE-INFO.txt","SGUARD-README.TXT","SHTODELATVAM.txt","SIFRE_COZME_TALIMATI.html","Sarah_G@ausi.com___","Sarah_G@ausi.com___*","ScreenLocker_x86.dll","Sifre_Coz_Talimat.html","SintaLocker.exe","SintaRun.py","Spreader_x86.dll","SsExecutor_x86.exe","StrutterGear.exe","Survey Locker.exe","TOTALLYLEGIT.EXE","TRY-READ-ME-TO-DEC.html","TUTORIEL.bmp","Tempimage.jpg","ThxForYurTyme.txt","TrumpHead.exe","UNLOCK_FILES_INSTRUCTIONS.html","UNLOCK_FILES_INSTRUCTIONS.txt","USPS_Delivery.doc","UnblockFiles.vbs","UselessDisk.exe","VIP72.exe","Vape Launcher.exe","VictemKey_*_*","WE-MUST-DEC-FILES.html","WHERE-YOUR-FILES.html","WannaCry.TXT","WannaCrypt 4.0.exe","Wannacry.exe","What happen to my files.txt","WhatHappenedWithFiles.rtf","WhatHappenedWithMyFiles.rtf","WindowsApplication1.exe","Wo_sind_meine_Dateien.htm*","YOUGOTHACKED.TXT","YOUR_FILES.HTML","YOUR_FILES.url","YOUR_FILES_ARE_DEAD.hta","YOUR_FILES_ARE_ENCRYPTED.HTML","YOUR_FILES_ARE_ENCRYPTED.TXT","YOUR_FILES_ARE_LOCKED.txt","YOU_MUST_READ_ME.rtf","Your files are locked !!!!.txt","Your files are locked !!!.txt","Your files are locked !!.txt","Your files are locked !.txt","Your files are now encrypted.txt","Your files encrypted by our friends !!! txt","Your files encrypted by our friends !!!.txt","YourID.txt","ZINO_NOTE.TXT","Zenis-*.*","Zenis-Instructions.html","[*]-HOW-TO-DECRYPT.txt","[KASISKI]","[KASISKI]*","[Lockhelp@qq.com].Gate","[amanda_sofost@india.com].wallet","_!!!_README_!!!_*","_!!!_README_!!!_*_ .txt","_!!!_README_!!!_*_.hta","_*_HOWDO_text.html","_*_README.hta","_*_README.jpg","_Adatok_visszaallitasahoz_utasitasok.txt","_CRYPTED_README.html","_DECRYPT_INFO_*.html","_DECRYPT_INFO_szesnl.html","_HELP_HELP_HELP_*","_HELP_HELP_HELP_*.hta","_HELP_HELP_HELP_*.jpg","_HELP_INSTRUCTION.TXT","_HELP_INSTRUCTIONS_.TXT","_HELP_Recover_Files_.html","_HELP_instructions.bmp","_HELP_instructions.txt","_HOWDO_text.html","_HOW_TO_Decrypt.bmp","_H_e_l_p_RECOVER_INSTRUCTIONS*.html","_H_e_l_p_RECOVER_INSTRUCTIONS*.png","_H_e_l_p_RECOVER_INSTRUCTIONS*.txt","_H_e_l_p_RECOVER_INSTRUCTIONS+*.html","_H_e_l_p_RECOVER_INSTRUCTIONS+*.png","_H_e_l_p_RECOVER_INSTRUCTIONS+*.txt","_How to restore files.*","_How_To_Decrypt_My_File_.*","_INTERESTING_INFORMACION_FOR_DECRYPT.TXT","_Locky_recover_instructions.bmp","_Locky_recover_instructions.txt","_README_*.hta","_README_.hta","_READ_ME_FOR_DECRYPT.txt","_READ_THI$_FILE_*","_RECOVER_INSTRUCTIONS.ini","_RECoVERY_+*.*","_RESTORE FILES_.txt","_WHAT_is.html","_XiaoBa_Info_.hta","_crypt","_help_instruct*.*","_how_recover*.html","_how_recover*.txt","_how_recover+*.html","_how_recover+*.txt","_how_recover.txt","_iWasHere.txt","_nullbyte","_ryp","_secret_code.txt","_如何解密我的文件_.txt","aboutYourFiles.*","allcry_upx.exe","anatova.exe","anatova.txt","bahij2@india.com","chilli.exe","cmdRansomware.*","confirmation.key","crjoker.html","cryptinfo.txt","cryptolocker.*","cscc.dat","damage@india.com*","de_crypt_readme.*","de_crypt_readme.bmp","de_crypt_readme.html","de_crypt_readme.txt","decipher_ne@outlook.com*","decoder.hta","decrypt all files*.bmp*","decrypt explanations.html","decrypt-instruct*.*","decrypt_Globe*.exe","decrypt_instruct*.*","decrypted_files.dat","decypt_your_files.html","default32643264.bmp","default432643264.jpg","delog.bat","diablo6-*.htm","dispci.exe","dllhost.dat","dummy_file.encrypted","ebay-msg.html","ebay_was_here","email-salazar_slytherin10@yahoo.com.ver-*.id-*-*.randomname-*","email-vpupkin3@aol.com*","enc_files.txt","encryptor_raas_readme_liesmich.txt","enigma.hta","enigma_encr.txt","exit.hhr.obleep","fattura_*.js","file0locked.js","filesinfo.txt","firstransomware.exe","hacked.txt","help-file-decrypt.enc","help_decrypt*.*","help_decrypt_your_files.html","help_file_*.*","help_instructions.*","help_recover*.*","help_recover_instructions*.bmp","help_recover_instructions*.html","help_recover_instructions*.txt","help_recover_instructions+*.BMP","help_recover_instructions+*.html","help_recover_instructions+*.txt","help_restore*.*","help_to_decrypt.txt","help_your_file*.*","how to decrypt aes files.lnk","how to decrypt*.*","how to get back you files.txt","how to get data.txt","how_decrypt.gif","how_recover*.*","how_to_back_files.html","how_to_decrypt*.*","how_to_recover*.*","how_to_recver_files.txt","how_to_unlock*.*","howrecover+*.txt","howto_recover_file.txt","howto_restore*.*","howtodecrypt*.*","howtodecryptaesfiles.txt","infpub.dat","install_tor*.*","keybtc@inbox_com","last_chance.txt","lblBitcoinInfoMain.txt","lblFinallyText.txt","lblMain.txt","les#.TXT","locked.bmp","loptr-*.htm","lukitus.html","matrix-readme.rtf","maxcrypt.bmp","message.txt","mood-ravishing-hd-wallpaper-142943312215.jpg","msptermthemes.exe","oor.","oor.*","ownertrust.txt","padcryptUninstaller.exe","paycrypt.bmp","payload.dll","petwrap.exe","popcorn_time.exe","pronk.txt","qwer.html","qwer2.html","qwerty-pub.key","random","ransomed.html","readme.hta","readme_decrypt*.*","readme_for_decrypt*.*","readme_liesmich_encryptor_raas.txt","recover.bmp","recover.txt","recoverfile*.txt","recovery+*.*","recovery_file.txt","recovery_key.txt","recoveryfile*.txt","redchip2.exe","restore_files.txt","restorefiles.txt","rtext.txt","ryukreadme.html","strongcrypt.bmp","structsstructs.exe","svchosd.exe","svchostt.exe","t.wry","tabDll*.dll","taskdl.exe","taskhsvc.exe","tasksche.exe","taskse.exe","tor.exe","tox.html","unCrypte@outlook.com*","vault.hta","vault.key","vault.txt","vesad","warning.txt","wcry.exe","wcry.zip","wie_zum_Wiederherstellen_von_Dateien.txt","winclwp.jpg","wormDll*.dll","x5gj5_gmG8.log","xort.txt","your_key.rsa","zXz.html","zcrypt.exe","zycrypt.*","zzzzzzzzzzzzzzzzzyyy","Инструкция по расшифровке.TXT","инструкция по оплате.txt")
	
	# ONLY if you use the Experiant download you may want to use the following commented variable because Experient does not supply exclusions (and that's a good thing).
	# To use this you just uncomment and populate it with your chosen file group exclusions
	# The "AntiransomwareFiltersMerge.py" generated json file manages this information for you but it is an extension to, and not included with the basic Experiant JSON format.
	# This variable cannot be an empty string (""), either leave it undefined or populate it with meaningful information.
	# legacy note - These are file group Exclude Files. They are not the same as SkipList.txt entries.
	# $FnameExtExclude = @("this_is_just_a_dummy_placeholder_string","replace_it_with_meaningful_information_if_necessary","excluded_file_specs")

	$LocalJsonFilePathAndPattern = $PSScriptRoot+"\"+"combined-"+$JSONfnamesubstring+"-????????_??????.json"

	$HoneyPotFileGroupName = "HoneyPotAllFilesWildcard"
	$HoneyPotsRapidSMBdisconnectFlagholder = "" # will be populated later based on command line boolean
	$HoneyPotFilters = @("*.*")
	# the following exclusions are so common that I think it's OK to exclude them by default, mostly dropped by curious legitimate users, let's not lock them out for this
	$HoneyPotExclusions = $("thumbs.db","desktop.ini")

	$RansomwareTemplateName = "RansomwareFnamesAndExtsCheck"
	$HoneyPotTemplateName = "RansomwareHoneyPotCheck"

	$TriggeredScriptStaticBaseName = "TriggeredDenySMBPermissions.PS1"
	# Creates a valid file path to store triggered script that is called by the FSRM screens
    # the path must exist before the triggered script can be created, the default is to use the same path as this script which definitely exists
	# replace the $PSCommandPath variable with an alternate location if you wish, it must already exist
    # we split the path to isolate the full path from the name of this script (which is always part of $PSCommandPath)
    $TriggeredScriptDestinationPath = Split-Path -Path $PSCommandPath
	$TriggeredScriptFullName = Join-Path -Path $TriggeredScriptDestinationPath -ChildPath $TriggeredScriptStaticBaseName

	# END - ADDITIONAL VARIABLES THAT NEED TO BE SET AND VALIDATED #

	# now we get to work
	# make sure a "source" has been setup in the event log, this should be first executable line so we catch any subsequent warnings and errors
	# we'll just force it blindly every time, detecting sources is too convoluted and this won't hurt anything
	New-EventLog -LogName $EventLog -Source $EventLoggingSource -ErrorAction SilentlyContinue
	$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nInformation:`nNormal script startup`n"
    # build a text list of all variables from the param block, format them for easy reading
    [string]$localformattedparmstring = (Get-Command -Name $PSCommandPath).Parameters | Format-Table -AutoSize @{ Label = "Key"; Expression={$_.Key}; }, @{ Label = "Value"; Expression={(Get-Variable -Name $_.Key -EA SilentlyContinue).Value}; } | Out-String
    $message = $message +"`nParam block variables and values:"+ $localformattedparmstring
	Write-Host $message
	Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 1 -EntryType Information -Message $message
	
	# The "Requires -Version 4" statement at the top is primarily to enforce that the script is being run as administrator
	# The rest of this script is compatible with version 3. You may override this version check if you're stuck with PS 3 but you must insure that you're running as admin.
	# For Windows 2012x you should add WMF 5.1 to your server which upgrades the PowerShell to version 5.1. See additional info in the notes. WMF 5.1 is standard in W2016 and W2019.
	Write-Host "`nTesting PowerShell version 4 or above"
	If ($PSVersionTable.PSVersion.Major -lt 4)
		{
		$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nError:`nWrong version of PowerShell detected`nThis script requires PowerShell version 4 or above.`n`nAborting script.`nIt is possible to override this requirement but you must insure you're running this script as administrator.`nA better alternative is to install Windows Management Framwork (WMF) 5.1`nSee the special PowerShell 3 instructions in this script.`n"
		$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
		Write-Host -ForegroundColor Red -BackgroundColor Black $message
		Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 2001 -EntryType Error -Message $message
		Exit
		}

	# test Windows version, Windows 2012 and above and server edition
	Write-Host "`nTesting for Windows 2012 or higher and Server edition"
	# get info for the running OS
	$OSinfoNow = Get-CimInstance -ClassName Win32_OperatingSystem -Property Version,Caption
	# perform a regex matching operation on the Version property as a string, matches nn.nn but not the second '.' or anything after, single line mode
	$OSinfoNow."Version" -match "(?s)^[0-9]+\.[0-9]+"
	# use the automatically populated $Matches array's first element, cast to float
	$WverFloat = [float]$Matches[0]
	# test for both server edition string and version number
	If ( -not (($OSinfoNow.Caption -like "*Server*") -and ($WverFloat -ge [float]6.2)))
		{
		$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nError:`nWrong version of Windows detected`nThis script will only run on Windows 2012 and higher, and will only run on Server editions of Windows.`n`nAborting script.`n"
		$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
		Write-Host -ForegroundColor Red -BackgroundColor Black $message
		Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 2002 -EntryType Error -Message $message
		Exit
		}

	Write-Host "`nTesting variables configured"
	If (-not $YesAllTheVariablesAreSetHowIWant)
		{
		$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nError:`nScript unconfigured`nThis script implements very critical security measures.`nIt is imperative that you understand and edit the configuration variables in this script.`nYou will find them in the param() block and in the begin{} section.`nWhen all the settings are configured how you want them use the`n -YesAllTheVariablesAreSetHowIWant `$True`nparameter and rerun this script.`n`nAborting script.`n"
		$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
		Write-Host -ForegroundColor Red -BackgroundColor Black $message
		Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 2003 -EntryType Error -Message $message
		Exit
		}

	Write-Host "`nInformation:`nVerifying existence of triggered script located at `"$TriggeredScriptFullName`"`n"        
	If (Test-Path -Path $TriggeredScriptFullName)
	    {
    	# we must convert this to a short/8.3 format path name because of how we have to wrap the command in double quotes for the FSRM screen command property, totally convoluted
	    # create a COM object that knows how to conver to a short path
	    $COMObjFnameConvert = New-Object -ComObject Scripting.FileSystemObject
	    $TriggeredScriptDestinationPath8dot3 = $COMObjFnameConvert.GetFolder($TriggeredScriptDestinationPath).ShortPath
	    # important!!!: no spaces in script's name, because the file doesn't exist yet we can't use the COM object magic we used just above, NO SPACES!
	    $TriggeredScriptFullName8dot3 = Join-Path -Path $TriggeredScriptDestinationPath8dot3 -ChildPath $TriggeredScriptStaticBaseName

	    # add rapid disconnect flag, otherwise leave empty string
	    If ($RansomewareScreenRapidSMBdisconnect -eq $true) { $RansomewareRapidSMBdisconnectFlagholder = "-RapidSMBdisconnect" }
	    #$TriggeredRansomwareCommandParm = "-Command `"& {"+$TriggeredScriptFullName8dot3+" -username '[Source Io Owner]'}`""
	    $TriggeredRansomwareCommandParm = "-Command `"& {"+$TriggeredScriptFullName8dot3+" "+$RansomewareRapidSMBdisconnectFlagholder+" -username '[Source Io Owner]'}`""

	    # add rapid disconnect flag, otherwise leave empty string
	    If ($HoneyPotsScreenRapidSMBdisconnect -eq $true) { $HoneyPotsRapidSMBdisconnectFlagholder = "-RapidSMBdisconnect" }
	    #$TriggeredHoneyPotCommandParm = "-Command `"& {"+$TriggeredScriptFullName8dot3+" -username '[Source Io Owner]'}`""
	    $TriggeredHoneyPotCommandParm = "-Command `"& {"+$TriggeredScriptFullName8dot3+" "+$HoneyPotsRapidSMBdisconnectFlagholder+" -username '[Source Io Owner]'}`""

	    Write-Host "FSRM Ransomware triggered script (8.3 format) command string is:`n$TriggeredRansomwareCommandParm"
	    Write-Host "FSRM Honey Pot triggered script (8.3 format) command string is:`n$TriggeredHoneyPotCommandParm"
	    }
	else
	    {
        $message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nError:`nA critical error has occurred locating $TriggeredScriptFullName.`nThe FSRM triggered lockouts will not function correctly until this error is corrected.`n`nAborting script.`n"
        $message = $message +"`nParam block variables and values:"+ $localformattedparmstring
        Write-Host -ForegroundColor Red -BackgroundColor Black $message
        Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 2004 -EntryType Error -Message $message
        Exit
        }

	#add the FSRM role if it doesnt exist
	Write-Host "`nVerifying FSRM is installed"
	If ((Get-WindowsFeature fs-resource-manager).installed -like "False")
		{
		$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nWarning:`nInstalling FSRM`nYou will only see this warning message when this script is installing the FSRM role.`nRead the following messages from the Windows installer carefully. You may need to reboot manually.`nRerun this script when the FSRM installation has finished.`nNote - for Windows 2012 and 2012r2 only:`nThe FSRM service can be a little unstable immediately after the FSRM role is installed.`nIf you see errors when you rerun this script then stop and restart the FSRM service and then rerun this script again.`n"
		$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
		Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
		Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 1001 -EntryType Warning -Message $message
		Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
		Exit
		}
	} # end Begin clause
  
Process
	{
	# we always need some sort of SMTP setup (this if clause will execute for both reinstallation of FSRM and partial installations that needed to be rebooted to complete, it's a kludge but very necessary)
	Write-Host "`nVerifying SMTP server and admin email address settings in FSRM"
	If (((Get-FsrmSetting).SmtpServer -ne $SMTPServer) -or ((Get-FsrmSetting).AdminEmailAddress -ne $AdminEmailTo))
		{
		$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nWarning:`nThe current global FSRM SMTP server and destination email address settings do not match this script's settings.`nThe current settings in this script are SMTP: `"$SMTPServer`" and Admin email: `"$AdminEmailTo`" .`nIf this is the first time you've run this script after installing FSRM then`nthe settings from the variables will be applied.`nIf this is not the first time you've run this script after installing FSRM then`nthe current settings in FSRM will be replaced with the values shown just above.`nYou will need to close and then reopen the FSRM manager to view the new settings because`nthere is no refresh option for global settings.`nFinally, use the FSRM manager to send a test message just to be sure everything works the way you expect.`n"
		$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
		Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
		Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 1002 -EntryType Warning -Message $message
		Set-FsrmSetting -SmtpServer $SMTPServer -AdminEmailAddress $AdminEmailTo  -FromEmailAddress $EmailFrom -CommandNotificationLimit 0 -EmailNotificationLimit 1 -EventNotificationLimit 0 -ReportFileScreenAuditEnable
		Write-Host "`nVerifying SMTP server and admin email reset"
		if ($? -ne $True)
			{
			# you should never get here but it is so important that we have to check the return value
			$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nError:`nA critical error has occurred setting the global settings in FSRM.`nSettings include SMTP server, admin email address, from email address, and notification timers.`nThe FSRM file screens will not function correctly until this error is corrected.`n`nAborting script.`n"
			$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
			Write-Host -ForegroundColor Red -BackgroundColor Black $message
			Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 2005 -EntryType Error -Message $message
			Exit
			}
		}

	# this is so important that we'll check every time the script is run, sorry to be heavy handed but you have no choice, this is a critical security issue
	# the command notification limit must be set to 0, anything but 0 will prevent the lockout script from running more than once within the timer interval
	# the event notification limit should be set to 0, we want every trigger to be logged in the Windows event logs
	Write-Host "`nVerifying command and event notification limits set to 0 (zero)"
	If (((Get-FsrmSetting).CommandNotificationLimit -ne 0) -or ((Get-FsrmSetting).EventNotificationLimit -ne 0))
		{
		$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nWarning:`nThe FSRM global settings for both Command Notification and Event Notification must be set to zero (0)`nThe triggered scripts and email notifications will not work reliably if the notification values are set to ANYTHING else.`nYou're seeing this message because the values were not zero. They will be reset to the correct values now.`n"
		$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
		Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
		Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 1003 -EntryType Warning -Message $message
		Set-FsrmSetting -CommandNotificationLimit 0 -EventNotificationLimit 0
		if ($? -ne $True)
			{
			$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nError:`nA critical error has occurred setting the global notification timers in FSRM.`nThe FSRM file screens will not function correctly until this error is corrected.`n`nAborting script.`n"
			$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
			Write-Host -ForegroundColor Red -BackgroundColor Black $message
			Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 2006 -EntryType Error -Message $message
			Exit
			}
		}

	# look for a json file with updated filters and exceptions, if not found then just use the defaults set in the variables
	If ($LegacyDownloadFiltersJson)
		{
		$message = "`nInformation:`nAttempting legacy download of ransomware filter list from $LegacyDownloadFiltersJsonURL`n"
		Write-Host $message
		Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 2 -EntryType Information -Message $message
		$FromJSONdata = Invoke-WebRequest $LegacyDownloadFiltersJsonURL | ConvertFrom-Json
		# testing $? does work here, but testing for null value is more comprehensive and tests json conversion too
		If ($FromJSONdata -eq $null)
			{
			$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nWarning:`nDownloading filters list from $LegacyDownloadFiltersJsonURL failed.`nUsing built-in defaults for now.`nMust be remediated for maximum protection.`n"
			$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
			Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
			Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 1004 -EntryType Warning -Message $message
			}
		Else
			{
			# download json read succesfully, apply to file group
			$message = "`nInformation:`nLegacy download of filters directly from $LegacyDownloadFiltersJsonURL succeeded.`n"
			$message = $message + "`nDownloaded filters timestamp: " + $FromJSONdata.lastUpdated
			Write-Host $message
			Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 3 -EntryType Information -Message $message
			Write-Host "`n"
			$FnameExtFilters = $FromJSONdata.filters
			}
		# now process IncludeList.txt and SkipList.txt, these are optional so just emit warning if missing, emit an info event upon success
		$TempIncludeListTxtPath = $PSScriptRoot + "`\IncludeList.txt"
		If (Test-Path -Path $TempIncludeListTxtPath)
			{
			# read the Include List file and appende to $FnameExtFilters
			$FnameExtFilters = $FnameExtFilters + (Get-Content -LiteralPath $TempIncludeListTxtPath | ForEach-Object {$_.Trim()})
			# dedupe
			$FnameExtFilters = $FnameExtFilters | Select-Object -Unique
			$message = "`nInformation:`nIncludeList.txt read successfully from $TempIncludeListTxtPath`n"
			Write-Host $message
			Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 12 -EntryType Information -Message $message
			}
		Else
			{
			$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nWarning:`nDid not find an IncludeList.txt file.`n"
			$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
			Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
			Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 1007 -EntryType Warning -Message $message
			}

		# remove SkipList.txt entries (equivalent of extended-data.allowed in the extended format JSON)
		$TempSkipListTxtPath = $PSScriptRoot + "`\SkipList.txt"
		If (Test-Path -Path $TempSkipListTxtPath)
			{
			# read in the filters that should be allowed, the Skip List
			$TempSkipList = Get-Content -LiteralPath $TempSkipListTxtPath | ForEach-Object {$_.Trim()}
			# now remove them from $FnameExtFilters
			$FnameExtFilters = $FnameExtFilters | Where-Object {$TempSkipList -notcontains $_}
			$message = "`nInformation:`nSkipList.txt read successfully from $TempSkipListTxtPath`n"
			Write-Host $message
			Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 13 -EntryType Information -Message $message
			}
		Else
			{
			$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nWarning:`nDid not find an IncludeList.txt file.`n"
			$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
			Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
			Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 1008 -EntryType Warning -Message $message
			}
		}
	Else
		{
		Write-Host "`nSearching for local JSON file matching:`n$LocalJsonFilePathAndPattern`n"
		$LocalJsonFile = Get-ChildItem -Path $LocalJsonFilePathAndPattern | Sort-Object -Property PSChildName | Select-Object -Last 1
		If ($LocalJsonFile -eq $null)
			{
			$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nWarning:`nNo input JSON file matching $LocalJsonFilePathAndPattern found.`nUsing built-in defaults for now.`nMust be remediated for maximum protection.`n"
			Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
			Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 1005 -EntryType Warning -Message $message
			}
		else
			{
			Write-Host "`nReading filters and exceptions from local JSON file:`n$LocalJsonFile`n"
			$FromJSONdata = Get-Content -Path $LocalJsonFile -Raw | ConvertFrom-Json
			# testing $? does work here, but testing for null value is more comprehensive and tests json conversion too
			If ($FromJSONdata -eq $null)
				{
				$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nWarning:`nThe Get-Content import from $LocalJsonFile filters file failed.`nUsing built-in defaults for now.`nMust be remediated for maximum protection.`n"
				$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
				Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
				Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 1006 -EntryType Warning -Message $message
				}
			Else
				{
				# local json read succesfully, apply to file group
				$message = "`nInformation:`nFilters data successfully imported from $LocalJsonFile`n"
				Write-Host $message
				Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 4 -EntryType Information -Message $message
				$FnameExtFilters = $FromJSONdata.filters
				$FnameExtExclude = $FromJSONdata.exceptions
				}
			}
		}

    # At this point we've settled on a set of filters, whether we downloaded them directly, used and input file, or just used the embedded filters.
    # No we validate the filters and reject any illegal file specs. We have to work around the fact that FSRM file groups accept * and ? wildcards.
    # init temp arrays
    $ValidatedFilters = @()
    $InvalidFilters = @()
    $FnameExtFilters | ForEach-Object {
        # make a copy of each filter, then replace the * and ? characters with ZZ and Y respecitively
        $scratch = $_
        $scratch = $scratch -replace '\*','ZZ'
        $scratch = $scratch -replace '\?','Y'
        # tests against the regex modified scratch version of the filter but copies the unmodified filter string to the appropriate array
        if (Test-Path -IsValid -Path $scratch)
            {
            # we'll use these to pass into FSRM
            $ValidatedFilters += $_
            }
        else
            {
            # these are just for output in text format in event log message, that's why the formatting is different than $ValidatedFilters
            $InvalidFilters += "`n" + $_
            }
        }
    # if there are any invalid filters then replace the filters with the validated list, then build warning message and emit
    if ($InvalidFilters.Count -gt 0)
        {
        $FnameExtFilters = $ValidatedFilters
        # now barf an event log warning with the invalid filter strings
        $message = "`Warning:`nInvalid input filters were detected. They will be skipped and not applied to the file group.`n"
        $message = $message +"`nInvalid filters found`n:"+$InvalidFilters
        Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
        Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 1007 -EntryType Warning -Message $message
        }

	# refresh is especially useful to clean up unneeded file screens for cases where a drive or share has been removed, (no error if none found)
	If($RefreshRansomewareScreens)
		{
		# delete all existing ransomeware file screens
		$message = "`nInformation:`nPurging $RansomwareTemplateName file screens`n"
		Write-Host $message
		Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 5 -EntryType Information -Message $message
		Get-FsrmFileScreen | Where-Object -Property Template -eq $RansomwareTemplateName | ForEach-Object {
            Remove-FsrmFileScreen -Confirm:$false -Path $_.Path
            Write-Host "`nRemoved file screen $_.Path"
            }
		}

	If ($RefreshHoneyPots) # honey pot refresh requested, delete all existing, (no error if none found)
		{
		# delete all existing honey pot file screens
		$message = "`nInformation:`nPurging $HoneyPotTemplateName file screens`n"
		Write-Host $message
		Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 6 -EntryType Information -Message $message
		# the following will match honey pot directories with a leading dot
		Get-FsrmFileScreen | Where-Object {($_.Template -eq $HoneyPotTemplateName) -and ($_.Path -Like "*$HoneyPotDirectoryNamePattern")} | ForEach-Object {
            Remove-FsrmFileScreen -Confirm:$false -Path $_.Path
            Write-Host "`nRemoved file screen $_.Path"
            }
		}

	$message = "`nInformation:`nCreating/Updating file groups`n"
	Write-Host $message
	Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 7 -EntryType Information -Message $message
	#Create File Group for FSRM ransomware file name detection, (no error if none found)
	If (Get-FsrmFileGroup | Where-Object -Property Name -eq $RansomeWareFileGroupName )
		{
		Write-Host "`nUpdating $RansomeWareFileGroupName file group"
		Set-FsrmFileGroup -name $RansomeWareFileGroupName -IncludePattern $FnameExtFilters -ExcludePattern $FnameExtExclude
		}
	Else
		{
		Write-Host "`nCreating $RansomeWareFileGroupName file group"
		New-FsrmFileGroup -name $RansomeWareFileGroupName -IncludePattern $FnameExtFilters -ExcludePattern $FnameExtExclude
		}

	#Create File Group for FSRM ransomware honey pot activity detection, (no error if none found)
	If (Get-FsrmFileGroup | Where-Object -Property Name -eq $HoneyPotFileGroupName )
		{
		Write-Host "`nUpdating $HoneyPotFileGroupName file group"
		Set-FsrmFileGroup -name $HoneyPotFileGroupName -IncludePattern $HoneyPotFilters -ExcludePattern $HoneyPotExclusions
		}
	Else
		{
		Write-Host "`nCreating $HoneyPotFileGroupName file group"
		New-FsrmFileGroup -name $HoneyPotFileGroupName -IncludePattern $HoneyPotFilters -ExcludePattern $HoneyPotExclusions
		}

	# !!! look at the end of the $action3 line, you must put a -KillTimeOut parameter with a Command type action, this line will silently fail without it but the new template command will bork with an "out of range" error
	$action1 = New-FsrmAction -Type Email -MailTo $TriggeredScriptEmailTo -Subject "Potential Ransomware Attack - Unauthorized file from the [Violated File Group] file group detected" -Body "User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which is not permitted on the server and suggests a ransomware attack has been attempted."
	$action2 = New-FsrmAction -Type Event -EventType Warning -Body "User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which is not permitted on the server and suggests a ransomware attack has been attempted."
	$action3Ransomware = New-FsrmAction -Type Command -SecurityLevel LocalSystem -Command "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -CommandParameters $TriggeredRansomwareCommandParm -WorkingDirectory $TriggeredScriptDestinationPath -ShouldLogError -KillTimeOut 1
	$action3HoneyPot = New-FsrmAction -Type Command -SecurityLevel LocalSystem -Command "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -CommandParameters $TriggeredHoneyPotCommandParm -WorkingDirectory $TriggeredScriptDestinationPath -ShouldLogError -KillTimeOut 1
	$message = "`nInformation:`nCreating/Updating file screen templates`n"
	Write-Host $message
	Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 8 -EntryType Information -Message $message
	# process the ransomware template
	If (Get-FsrmFileScreenTemplate | Where-Object -Property Name -eq $RansomwareTemplateName) # It must have existed already so we'll just update it
		{
		# note: we are pushing this update to ALL derived file screens, not just the directly matching file screens
		Write-Host "`nUpdating $RansomwareTemplateName template"
		Set-FsrmFileScreenTemplate -Name $RansomwareTemplateName -UpdateDerived -Active:$RansomwareTemplateIsActive -IncludeGroup $RansomeWareFileGroupName -Description "This template traps files with extensions on the likely ransomware list" -Notification $action1,$action2,$action3Ransomware
		}
	Else
		{
		Write-Host "`nCreating $RansomwareTemplateName template"
		New-FsrmFileScreenTemplate -Name $RansomwareTemplateName -Active:$RansomwareTemplateIsActive -IncludeGroup $RansomeWareFileGroupName -Description "This template traps files with extensions on the likely ransomware list" -Notification $action1,$action2,$action3Ransomware
		}
	#process the honey pot templates
	# note:
	# the -Active:$false is not well documented but this is the only way to make the template passive, passive will allow the user to keep creating files until the access is revoked
	# this template should always be passive to allow that bad guys to create files and not detect an access denied condition
	If (Get-FsrmFileScreenTemplate | Where-Object -Property Name -eq $HoneyPotTemplateName) # It must have existed already so we'll just update it
		{
		# note: we are pushing this update to ALL derived file screens, not just the directly matching file screens
		Write-Host "`nUpdating $HoneyPotTemplateName template"
		Set-FsrmFileScreenTemplate -Name $HoneyPotTemplateName -UpdateDerived -Active:$false -IncludeGroup $HoneyPotFileGroupName -Description "This template detects any file creation in our honey pot directories." -Notification $action1,$action2,$action3HoneyPot
		}
	Else
		{
		Write-Host "`nCreating $HoneyPotTemplateName template"
		New-FsrmFileScreenTemplate -Name $HoneyPotTemplateName -Active:$false -IncludeGroup $HoneyPotFileGroupName -Description "This template detects any file creation in our honey pot directories." -Notification $action1,$action2,$action3HoneyPot
		}

	# Note:
	# You MAY use both the monitoring drives and the monitoring share methods together. Since roots of drives can't be shared there will never be direct conflicts.
	# File screens at lower levels (farther from the root) of the file system always override the file screens applied at higher levels (nearer to the root).
	# There is no Set-FsrmFileScreen PowerShell command because they are modified by their templates.
	If ($ApplyRansomewareScreenToDrives -or $ApplyRansomewareScreenToShares)
		{
		$message = "`nInformation:`nCreating ransomeware file screens`n"
		Write-Host $message
		Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 10 -EntryType Information -Message $message
		# we're excluding the C: drive root by default, note $_.DeviceID is essentially a path to the root, that's why it works here
		If ($ApplyRansomewareScreenToDrives)
			{
			Get-CimInstance -Class CIM_LogicalDisk | 
			Where-Object {($_.DriveType -eq 3) -and ($_.DeviceID -ne "C:")} | 
			ForEach-Object {If (-not (Get-FsrmFileScreen -Path $_.DeviceID -ErrorAction SilentlyContinue)) {New-FsrmFileScreen -Path $_.DeviceID -Template $RansomwareTemplateName}}
			# since we're never going to apply a drive level screen to C: we need to apply the screen template to all shares on C: except those under C:\Windows
			# this is an arbitrary decision on my part, recode as necessary
			Get-SmbShare | Select-Object -Property * | 
			Where-Object {($_.Special -ne "True") -and ($_.ShareType -eq "FileSystemDirectory") -and ($_.Path -like "C:\*") -and ($_.Path -notlike "C:\Windows\*")} | 
			ForEach-Object {If (-not (Get-FsrmFileScreen -Path $_.Path -ErrorAction SilentlyContinue)) {New-FsrmFileScreen -Path $_.Path -Template $RansomwareTemplateName}}
			}

		# find all shares that are not Special (eg C$) AND that are FileSystemDirectory AND are not under C:\Windows ie NETLOGON,SCRIPTS,etc. (because they are not "Special")
		# FSRM is smart enough to only allow passive monitoring in the sensitive directories like NETLOGON, so you could always delete the file screens later
		# skips any shares that were already setup above
		If ($ApplyRansomewareScreenToShares)
			{
			Get-SmbShare | Select-Object -Property * | 
			Where-Object {($_.Special -ne "True") -and ($_.ShareType -eq "FileSystemDirectory") -and ($_.Path -notlike "C:\Windows\*")} | 
			ForEach-Object {If (-not (Get-FsrmFileScreen -Path $_.Path -ErrorAction SilentlyContinue)) {New-FsrmFileScreen -Path $_.Path -Template $RansomwareTemplateName}}
			}
		}

	# monitor all our honey pot directories for any file creation, we're only applying this to matching directories under shares
	If ($ApplyHoneyPots)
		{
		$message = "`nInformation:`nCreating honey pot file screens`n"
		Write-Host $message
		Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 11 -EntryType Information -Message $message
		$MatchedHoneyPotDirs = Get-SmbShare | Select-Object -Property * | 
		Where-Object {($_.Special -ne "True") -and ($_.ShareType -eq "FileSystemDirectory")  -and ($_.Path -notlike "C:\Windows\*")} | 
		ForEach-Object -Process {Get-ChildItem -Path $_.Path -Force -ErrorAction SilentlyContinue -Directory -Filter $HoneyPotDirectoryNamePattern}
		If ($HoneyPotDirectoryNameWildcardMatchesLeadingDot)
			{
			# if first char is ? then replace with . in new variable
			$HoneyPotDirectoryNamePatternWithLeadingDotSubst = $HoneyPotDirectoryNamePattern -replace '^\?','.'
			# append matching to list
			$MatchedHoneyPotDirs += Get-SmbShare | Select-Object -Property * | 
			Where-Object {($_.Special -ne "True") -and ($_.ShareType -eq "FileSystemDirectory")  -and ($_.Path -notlike "C:\Windows\*")} | 
			ForEach-Object -Process {Get-ChildItem -Path $_.Path -Force -ErrorAction SilentlyContinue -Directory -Filter $HoneyPotDirectoryNamePatternWithLeadingDotSubst}
			}

		$MatchedHoneyPotDirs | Select-Object -Property FullName | 
		ForEach-Object {If (-not (Get-FsrmFileScreen -Path $_.FullName -ErrorAction SilentlyContinue)) {New-FsrmFileScreen -Path $_.FullName -Template $HoneyPotTemplateName}}
		}
	$message = "FSRM-Anti-ransomware.ps1 Script version: " + $CurrentVersion + "`nInformation:`nNormal script shutdown`n"
	$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
	Write-Host $message
	Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 999 -EntryType Information -Message $message
	} # end Process clause
}
InstallUpdate-FSRMRansomwareScreening
