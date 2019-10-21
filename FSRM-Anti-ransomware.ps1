#Requires -Version 4 -RunAsAdministrator
param(
	[string]$SMTPServer = "127.0.0.1",
	# this builds a default string using the computer name and the domain name, you may replace this with any string you choose
	# suitable for servers that are domain joined
	[string]$EmailFrom = "FSRM-"+(Get-CIMInstance -Class CIM_ComputerSystem).Name+"@"+(Get-CIMInstance -Class CIM_ComputerSystem).Domain,
	# for stand-alone or custom configuration use something like -EmailFrom "FSRM-Triggered@example.com"
	# notification emails may be sent to more than one recipient, seperate multiple recipients with a semicolon (eg. "admin1@example.com:admin2@example.com")
	[string]$AdminEmailTo = "securityadmin@example.com",

	# while you can download filters directly it is better to use the included Python script that generates JSON input data and carries all your options forward
	# legacy download will download a combined.json file containing filters AND modify the filter list based on local legacy IncludeList.txt and SkipList.txt
	#	! must be in the same directory as this script ! (will not relocate like legacy scripts do)
	[bool]$LegacyDownloadFiltersJson = $false, # boolean inputs are either $true or $false, they require the dollar sign to precede the value, recommend leaving $false
	[string]$LegacyDownloadFiltersJsonURL = "https://fsrm.experiant.ca/api/v1/combined",  # they do a great job keeping their filters up to date

	[string]$JSONfnamesubstring = "extended", # put client name, server name, etc. to match your input JSON file

	# !! be sure you undertand what "passive" and "active" mean in the context of FSRM before overriding !!
	#	active sends email alerts and actively blocks access to files (good for production files, prevents any ransomware files, may still allow encryption of files)
	#	passive sends email alerts but does not block access to files (good for honey pots so you can do forensics on encrypted files and money requests)
	[bool]$RansomwareTemplateIsActive = $true,

	# you need to set your own directory names, the bad guys can read this too, keep the '?' to match the leading sorting characters in the included sample zip file
	# instruct your users to avoid these honey pot directories but they must be RW accessible to all
	[string]$HoneyPotDirectoryNamePattern = "?ITDept_DoNotTamperWithContents",

	# these are the email address FSRM variables used for notification when a file screen is triggered
	# these are not email addresses that you enter, you use FSRM variables
	# see the included "FSRM email form variables.txt" or the FSRM online help for the definitions of these FSRM variables 
	[string]$TriggeredScriptEmailTo = "[Admin Email];[Source Io Owner Email]", # you may not want to notify the owner, $TriggeredScriptEmailTo = "[Admin Email]"

	[bool]$ApplyRansomewareScreenToDrives = $true, # ransomware file screens will be applied to the roots of all drives except C: (the OS drive), special case - shares on C: will be protected
	[bool]$ApplyRansomewareScreenToShares = $true, # this will cause the ransomware file screens to all "non-special" file shares excluding any under C:\Windows
	[bool]$RefreshRansomewareScreens  = $true,  # when true this causes the existing file screens to be deleted before being reapplied

	[bool]$ApplyHoneyPots = $true, # this will cause the honey pot file screens to be applied to all shared directories that match the HoneyPotDirectoryNamePattern spec
	[bool]$RefreshHoneyPots = $true,  # when true this causes the existing honey pot file screens to be deleted before being reapplied

	# the configuration of this script covers a lot of important critical security issues
	# setting the following variable to $true is your acknowledgement that you understand all the settings (two locations)
		# param() block at the top of the script
		# additional variables at the top of the begin{} section
	# !!! this script implements critical security measures
	# !!! You must understand and edit these variables in the Begin section before you run the script.
	# !!! The SMTP server and the EmailTo variables must be set to insure prompt notifications.
	# !!! The CommandNotificationLimit must be set to 0, the EventNotificationLimit should be set to 0, both are hard coded in this script
	# script editing note: do not set this to mandatory as that would bypass event logging and information display
	[bool]$YesAllTheVariablesAreSetHowIWant = $false
	)
<#
Usage:
	Install-and-Update-FSRM-Anti-ransomware.ps1
	This script does not use command line parameters. Edit the variables in the "begin" clause as needed.
Version:
	see $CurrentVersion variable below
Requirements:
	Windows Server 2012 (Windows 6.2) or above with all updates applied
	PowerShell 4 or above recommended
		For Windows 2012(r1) you should install the WMF 5.1, recommended for Windows 2012r2 as well
		see notes for PowerShell 3 workaround
Notes:
	Important! This file must be UTF-8 for the embedded ransomware file names to render properly. Also, save this with a BOM so that Windows will "guess" correctly.
		Compare the following two lines. One is Unicode and the other ASCII. If they look completely different from each other then you've lost Unicode encoding!
			Α-Uиịϲоԁḙ-Ω		(Unicode, mix of Greek, Cyrillic, and Latin characters, and begins with Greek alpha and ends with Greek omega)
			A-Unicode-O		(ASCII, plain text)
		(A BOM shouldn't ever be necessary with UTF-8 Unicode, but the PowerShell ISE still needs it. Be sure this file has a BOM.)
	Important! You must leave the FSRM global setting Notification Limits->Command notification (minutes): set to 0 (zero). It will be reset each time this script runs.
		If you must have this set to something else then you'll need to reset the FSRM service in the triggered scripts each time they run.
		You "should" also have the event notification set to 0 so that each event goes to the Windows event log
		The is because we're using a mechanism (FSRM file screens) that was originally intended only for notification messages. 
			We are re-purposing it for security actions. Be strict!
	Important! This script assumes that you DO NOT already have file screens applied to drives/shares captured by this script.
		Only one screen is allowed per directory (share,drive,directory)
		If other screens have been applied to the same shares / drive points then this script will fail at creating new file screens on those points.
	Important! When you run this script be sure you read and remediate all errors and warnings shown on the screen and shown in the Windows Application event log.
		When this script runs correctly there will be no warnings or errors.
		exception:
			There may be warnings (not errors) about the email configuration.
			The warnings will clear when you rerun this script a second time, after which the warnings will stay cleared.
	Edit the variables in the "Begin" section or in a custome pre-load script to match your SMTP setup and admin email.
	If FSRM is already installed you should still run this script. It will take care of the parts that we need for ransomware detection.
	Special note for installing FSRM on Windows 2012 and 2012r2
		After installing FSRM you will probably need to reboot the OS manually. Take note of the message on the screen telling you to do so.
		When you run this script the second time to install all the file screens you may still see quite a few errors. Just stop and then restart the FSRM service.
		You can avoid all this trouble by either installing WMF 5.1 or manually installing FSRM and rebooting first. This is for Windows 2012 versions only.
			requires .NET 4.5.2 or higher, will install with lower versions without error but functionality will be impacted
			if you are fully patched then you will be running at least v4.8.x even on W2012r1
			check version installed here:
				HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full
	PowerShell version 3 - Yes, you can run this script but you must make sure you're running it as administrator. Here's what to do in two simple steps:
		1. remove the # Requires -Version 4 line from the top of this script
		2. change the test "If ($PSVersionTable.PSVersion.Major -lt 4)" to "If ($PSVersionTable.PSVersion.Major -lt 3)"
	If the global settings in the FSRM management console look empty right after you've run this script then just restart the management console to make them show.
		The settings are there, you just can't see them because there's no refresh option at the top level of the FSRM manager.	
	The option to download a filters list from https://fsrm.experiant.ca assumes that you have initialized your Internet Explorer.
		The Invoke-WebRequest command uses the Internet Explorer engine. Internet Explorer must be setup and your settings must allow the download. Don't know Edge impact.
#>
function InstallUpdate-FSRMRansomwareScreening
{
Begin
	{
	# BEGIN - ADDITIONAL VARIABLES THAT NEED TO BE SET AND VALIDATED #
	$EventLog = "Application"
	$EventLoggingSource = "FSRM-AntiRansomwareScript"
	$CurrentVersion = "2.3.0"

	$RansomeWareFileGroupName = "RansomwareFnamesAndExt"
	# double check that this file is UTF-8, this embedded filters list contains names in Cyrillic, Portuguese, Spanish, Chinese, etc. see the top of this script
	$FnameExtFilters = @("! ПРОЧТИ МЕНЯ !.html","!! RETURN FILES !!.txt","!!! HOW TO DECRYPT FILES !!!.txt","!!! READ THIS - IMPORTANT !!!.txt","!!!!!ATENÇÃO!!!!!.html","!!!!!SAVE YOUR FILES!!!!.txt","!!!!RESTORE_FILES!!!.txt","!!!-WARNING-!!!.html","!!!-WARNING-!!!.txt","!!!GetBackData!!!.txt","!!!INSTRUCTION_RNSMW!!!.txt","!!!READ_IT!!!.txt","!!!READ_TO_UNLOCK!!!.TXT","!!!README!!!*.rtf","!!!ReadMeToDecrypt.txt","!!!SAVE YOUR FILES!.bmp","!## DECRYPT FILES ##!.txt","!#_DECRYPT_#!.inf","!#_How_to_decrypt_files_#!","!#_How_to_decrypt_files_$!.txt","!-GET_MY_FILES-!.*","!=How_to_decrypt_files=!.txt","!_!email__ prusa@goat.si __!..PAYMAN","!____________DESKRYPT@TUTAMAIL.COM________.rar","!_HOW_RECOVERY_FILES_!.txt","!_HOW_TO_RESTORE_*.txt","!_RECOVERY_HELP_!.txt","!_ИНСТРУКЦИЯ_!.txt","!back_files!.html","!Decrypt-All-Files-*.txt","!DMALOCK3.0*","!ENC","!GBLOCK_INFO.rtf","!INSTRUCTI0NS!.TXT","!OoopsYourFilesLocked!.rtf","!PEDANt_INFO!.rtf","!Please Read Me!.txt","!QH24_INFO!.rtf","!READ.htm","!readme.*","!README_GMAN!.rtf","!README_GRHAN!.rtf","!Recovery_*.html","!Recovery_*.txt","!satana!.txt","!SBLOCK_INFO!.rtf","!WannaDecryptor!.exe.lnk","!Where_are_my_files!.html","# DECRYPT MY FILES #.html","# DECRYPT MY FILES #.txt","# DECRYPT MY FILES #.vbs","# How to Decrypt Files.txt","# README.hta","###-READ-FOR-HELLPP.html","#_#ReadMe#_#.rtf","#_#WhatWrongWithMyFiles#_#.rtf","#_DECRYPT_ASSISTANCE_#.txt","#_RESTORING_FILES_#.TXT","#HELP-DECRYPT-FCRYPT1.1#.txt","#HOW_DECRYPT_FILES#.html","#HOW_TO_UNRIP#.txt","#NEWRAR_README#.rtf","#README_GMAN#.rtf","#RECOVERY-PC#.*","#RECOVERY_FILES#.*","#RECOVERY_FILES#.txt","$%%! NOTE ABOUT FILES -=!-.html","$RECYCLE.BIN.{*-*-*-*}","(encrypted)","(encrypted)*","* .tdelf","* .vCrypt1","*!DMAlock*","*!recover!*.*","*+recover+*.*","*-DECRYPT.html","*-DECRYPT.txt","*-filesencrypted.html","*-Lock.onion","*-PLIIKI.txt","*-recover-*.*","*-webmafia@asia.com_donald@trampo.info","*.!emc","*.#","*.##___POLICJA!!!___TEN_PLIK_ZOSTA","*.##ENCRYPTED_BY_pablukl0cker##","*.#__EnCrYpTED_BY_dzikusssT3AM_ransomware!__#","*.#Locky","*.*.sell","*.*cry","*.*crypto","*.*darkness","*.*exx","*.*GEFEST","*.*kb15","*.*kraken","*.*locked","*.*nochance","*.*obleep","*.+jabber-theone@safetyjabber.com","*...Files-Frozen-NEED-TO-MAKE-PAYMENT…","*..txt","*.0000","*.010001","*.0402","*.08kJA","*.0day","*.0wn3dyou","*.0x0","*.0x004867","*.0x009d8a","*.101","*.1500dollars","*.1999","*.1btc","*.1txt","*.24H","*.2cXpCihgsVxB3","*.2du1mj8","*.2k19","*.2k19sys","*.2lwnPp2B","*.2xx9","*.31342E30362E32303136*","*.31392E30362E32303136_*","*.3301","*.3674AD9F-5958-4F2A-5CB7-F0F56A8885EA","*.3nCRY","*.3ncrypt3d","*.3P7m","*.3RNu","*.449o43","*.490","*.491","*.492","*.4k","*.4rwcry4w","*.4x82N","*.61yhi","*.63vc4","*.666","*.666decrypt666","*.686l0tek69","*.6db8","*.6FKR8d","*.707","*.725","*.726","*.73i87A","*.777","*.7h9r","*.7z.encrypted","*.7zipper","*.8637","*.888","*.8lock8","*.911","*.96e2","*.@decrypt2017","*.@decrypt_2017","*.[1701222381@qq.com].ETH","*.[absonkaine@aol.com].phoenix","*.[actum_signum@aol.com].onion","*.[admin@hoist.desi].*.WALLET","*.[adobe-123@tutanota.com].ETH","*.[amagnus@india.com].wallet","*.[amber777king@cock.li].amber","*.[assistance@firemail.cc].nuclear","*.[avalona.toga@aol.com].blocking","*.[avflantuheems1984@aol.com].adobe","*.[backdata@cock.li].CreamPie","*.[backtonormal@foxmail.com].adobe","*.[bacon@oddwallps.com].java","*.[Bas_ket@aol.com].java","*.[batmanbitka1@cock.li].arena","*.[BaYuCheng@yeah.net].china","*.[bitcharity@protonmail.com].com","*.[black.world@tuta.io].nuclear","*.[blellockr@godzym.me].bkc","*.[blind@cock.li].blind","*.[BRAINCRYPT@INDIA.COM].BRAINCRYPT","*.[Brazzers@aolonline.top].arena","*.[btc2018@tutanota.de].meduza","*.[btc@fros.cc].btc","*.[btccrypthelp@cock.li].ETH","*.[buy-decryptor@pm.me]","*.[china-decryptor@pm.me]","*.[cho.dambler@yandex.com]","*.[costelloh@aol.com].phoenix","*.[crab7765@gmx.de].crab","*.[crypt1style@aol.com].MERS","*.[crypted_files@qq.com].aqva","*.[crysis@life.com].*.WALLET","*.[cyberwars@qq.com].war","*.[decodingfiles@tuta.io].java","*.[decrypthelp@qq.com].java","*.[decrypthelper@protonmail.com].phobos","*.[decryptmyfiles@qq.com].ETH","*.[decryptprof@qq.com].ETH","*.[DonovanTudor@aol.com].bat","*.[drwho888@mail.fr].888","*.[dsupport@protonmail.com]","*.[embrace@airmail.cc].embrace","*.[Enigma1crypt@aol.com].ETH","*.[epta.mcold@gmail.com]","*.[epta.mcold@gmail.com],","*.[eV3rbe@rape.lol].eV3rbe","*.[everbe@airmail.cc].everbe","*.[everest@airmail.cc].EVEREST","*.[evil@cock.lu].EVIL","*.[File-Help@India.Com].mails","*.[fileslocker@pm.me]","*.[Filesreturn247@gmx.de].lock","*.[firmabilgileri@bk.ru]","*.[frazeketcham@cnidia.com].eth.hv88g2","*.[GOFMEN17@YA.RU],CRP","*.[grethen@tuta.io]","*.[GuardBTC@cock.li].java","*.[gustafkeach@johnpino.com].ad","*.[Hardcorr@protonmail.com].java","*.[Hardcorrr@protonmail.com].java","*.[help24decrypt@cock.li","*.[help24decrypt@cock.li]","*.[helpfilerestore@india.com].ETH","*.[ID-][].JSWRM","*.[ID62133703]","*.[ID=xxxxxxx2uJ][Mail=letitbedecryptedzi@gmail.com].Lazarus","*.[ID=XXXXXXXXXX][Mail=unlockme123@protonmail.com].Lazar","*.[insane@airmail.cc].insane","*.[Kromber@tutanota.com]","*.[lockhelp@qq.com].gate","*.[MailPayment@decoder.com].ETH","*.[maxicrypt@cock.li].maxicrypt","*.[MAXVISION@SECMAIL.PRO].CRIPTOGRAFADO","*.[mercarinotitia@qq.com].adobe","*.[mich78@usa.com]","*.[mixon.constantine@aol.com].gamma","*.[mr.yoba@aol.com].yoba","*.[mrbin775@gmx.de].bin","*.[mrpeterson@cock.li].GFS","*.[NO.TORP3DA@PROTONMAIL.CH].WALLET","*.[notopen@countermail.com].NOT_OPEN","*.[oron@india.com].dharma","*.[pain@cock.lu].pain","*.[pain@onefinedstay.com].java","*.[papillon9275]","*.[paradisecity@cock.li].arena","*.[parambingobam@cock.li].adobe","*.[paydecryption@qq.com].brrr","*.[payransom@qq.com].adobe","*.[PINGY@INDIA.COM]","*.[plombiren@hotmail.com].plomb","*.[randal_inman@aol.com].help","*.[raphaeldupon@aol.com].ETH","*.[resque@plague.desi].scarab","*.[restorehelp@qq.com].java","*.[satan2018@protonmail.com].java","*.[Sepsis@protonmail.com].SEPSIS","*.[SHIELD0@USA.COM].*.WALLET","*.[skeleton@rape.lol].skeleton","*.[slaker@india.com]*.wallet","*.[SSSDKVNSDFITD]","*.[staRcRypt@tutanota.com].omerta","*.[stopencrypt@qq.com].adobe","*.[stopstorage@qq.com].java","*.[supp01@arimail.cc].napoleon","*.[suupport@protonmail.com].scarab","*.[teroda@bigmir.net].masterteroda@bigmir.net","*.[thedecrypt111@qq.com].ETH","*.[thunderhelp@airmail.cc].thunder","*.[ti_kozel@lashbania.tv].костя","*.[Traher@Dr.Com]","*.[Unlock24@cock.li].combo","*.[velasquez.joeli@aol.com]","*.[volcano666@tutanota.de].volcano","*.[w_decrypt24@qq.com].zq","*.[w_unblock24@qq.com].ws","*.[welesmatron@aol.com].btc","*.[writehere@qq.com].btc","*.[XAVAX@PM.ME].omerta","*.[yoursalvations@protonmail.ch].neverdies@tutanota.com","*.[zoro4747@gmx.de].zoro","*.__dilmaV1","*._AiraCropEncrypted!","*._Crypted","*._raphaeldupon@aol.com_.btc","*._ryp","*.a19","*.a5zfn","*.A604AF9070","*.a800","*.A95436@YA.RU","*.a990","*.A9V9AHU4","*.aa1","*.aaa","*.aajf","*.abc","*.acc","*.access","*.actin","*.Acton","*.Acton.id[1AE26935-1085].[hadleeshelton@aol.com].Acton","*.actor","*.ACTUM","*.Acuf2","*.acute","*.adage","*.adam","*.Adame","*.adapaterson@mail.com.mkmk","*.adk","*.ADMIN@BADADMIN.XYZ","*.adobe","*.adobee","*.AdolfHitler","*.ADR","*.AES","*.aes!","*.AES-NI","*.aes128ctr","*.AES256","*.aes_ni","*.aes_ni_0day","*.aescrypt","*.aesir","*.AFD","*.aga","*.airacropencrypted!","*.akaibvn","*.akira","*.albertkerr94@mail.com.m5m5","*.Alcatraz","*.aleta","*.AlfaBlock","*.alien","*.alilibat","*.Alkohol","*.allcry","*.alosia","*.altdelete@cock.li.district","*.am","*.amba","*.amber","*.Amigo","*.amnesia","*.anami","*.andonio","*.android","*.andymarvin","*.angelamerkel","*.AngleWare","*.animus","*.ANNABELLE","*.Annabelle2","*.anon","*.anonimus.mr@yahoo.com","*.anonymous","*.antihacker2017","*.anubi","*.ap19","*.aqva","*.area","*.arena","*.areyoulovemyrans","*.AreYouLoveMyRansFile","*.armadilo1","*.Armage","*.aRpt","*.arrow","*.ARTEMY","*.artilkilin@tuta.io.wq2k","*.asasin","*.asdasdasd","*.ATLAS","*.Atom","*.au1crypt","*.AUDIT","*.AUF","*.Aurora","*.auw2w2g0","*.AVco3","*.axx","*.AYE","*.AZER","*.azero","*.b0ff","*.B10CKED","*.b29","*.b5c6","*.b89b","*.backup","*.BadNews","*.bagi","*.BaLoZiN","*.bam!","*.bananaCrypt","*.banjo","*.BARRACUDA","*.BarRax","*.bart","*.bart.zip","*.basilisque@protonmail_com","*.basslock","*.BAWSUOOXE","*.bbqb","*.BD.Recovery","*.BDKR","*.Bear","*.beef","*.beep","*.beer","*.BeethoveN","*.beets!Ransom","*.BELGIAN_COCOA","*.berost","*.berosuce","*.besub","*.betta","*.better_call_saul","*.bgCIb","*.bgtx","*.BIG1","*.BIG4+","*.Bill_Clinton@derpymailorg","*.billingsupp","*.bip","*.birbb","*.bit","*.Bitconnect","*.bitkangoroo","*.bitstak","*.bizer","*.bk666","*.bkc","*.bkp","*.black007","*.BlackHat","*.BlackPink","*.BlackRouter","*.blackruby","*.blank","*.bleep","*.bleepYourFiles","*.blind","*.blind2","*.bliun","*.bloc","*.blocatto","*.bloccato","*.block","*.block_file12","*.blocked","*.Blocked2","*.bloked","*.blower","*.Blower@india.com","*.BMCODE","*.bmn63","*.bmps@tutanota.com.major","*.bomber","*.BONUM","*.booknish","*.boooam@cock_li","*.boost","*.bopador","*.boris","*.BORISHORSE","*.boston","*.braincrypt","*.bRcrypT","*.breaking bad","*.breaking_bad","*.breeding123","*.brickr","*.bript","*.browec","*.brrr","*.BRT92","*.brusaf","*.btc","*.btc -help-you","*.btc-help-you","*.btc.kkk.fun.gws","*.btcbtcbtc","*.btchelp@xmpp.jp","*.BtcKING","*.btcware","*.btix","*.budak","*.bufas","*.BUGWARE","*.bunny","*.burn","*.BUSH","*.bvjznsjlo","*.C0rp0r@c@0Xr@","*.c300","*.CAGO","*.cammora","*.canihelpyou","*.cap","*.carcn","*.carote","*.cassetto","*.cawwcca","*.cbf","*.cbs0z","*.cbu1","*.ccc","*.cccmn","*.CCCRRRPPP","*.cdrpt","*.CEBER3","*.cekisan","*.cerber","*.cerber2","*.cerber3","*.cerber6","*.Cerber_RansomWare@qq.com","*.CerBerSysLocked0009881","*.cesar","*.cezar","*.cezor","*.cfk","*.cfm","*.CHAK","*.charck","*.charcl","*.charm","*.Chartogy","*.CHE808","*.chech","*.checkdiskenced","*.cheetah","*.chekyshka","*.chifrator@qq_com","*.CHIP","*.choda","*.CHRISTMAS","*.CIFGKSAFFSFYGHD","*.CIOP","*.cizer","*.CK","*.clf","*.clinTON","*.Clop","*.cloud","*.cmb","*.cmsnwned","*.cnc","*.cobra","*.cock.email","*.cock.li","*.cockista","*.code","*.coded","*.coder007@protonmail.com","*.codnat","*.codnat1","*.codnet","*.codnet1","*.codyprince92@mail.com.ovgm","*.coharos","*.coin","*.colecyrus@mail.com.b007","*.COLORIT","*.com2","*.combo","*.CommonRansom","*.comrade","*.condat","*.CONFICKER","*.contact-me-here-for-the-key-admin@adsoleware.com","*.Contact_Here_To_Recover_Your_Files.txt","*.CONTACT_TARINEOZA@GMAIL.COM","*.CONTACTUS","*.COPAN","*.corrupted","*.cosakos","*.country82000","*.coverton","*.CQQUH","*.CQXGPMKNR","*.cr020801","*.Crab","*.crabs","*.CRABSLKT","*.CRADLE","*.craftul","*.crash","*.crashed","*.crazy","*.creeper","*.cRh8","*.crime","*.crinf","*.cripted","*.criptiko","*.criptokod","*.cripton","*.cripttt","*.crjocker","*.crjoker","*.croc","*.CROWN","*.CROWN!?","*.crptd","*.crptrgr","*.CRPTXXX","*.CRRRT","*.cry","*.Cry128","*.Cry36","*.Cry9","*.crybrazil","*.crying","*.cryp1","*.crypt","*.crypt1","*.crypt12","*.crypt2019","*.crypt38","*.crypt888","*.crypte","*.crypted","*.crypted!Sample","*.CRYPTED000007","*.crypted034","*.crypted_bizarrio@pay4me_in","*.crypted_file","*.crypted_marztoneb@tutanota_de","*.crypted_pony_test_build*","*.crypted_pony_test_build_xxx_xxx_xxx_xxx_xxx","*.CryptedOpps","*.cryptes","*.cryptfile","*.cryptgh0st","*.crypto","*.CRYPTOBOSS","*.CRYPTOBYTE","*.cryptoid","*.cryptojoker","*.cryptolocker","*.Crypton","*.cryptoNar","*.CRYPTOSHIEL","*.CRYPTOSHIELD","*.cryptotorlocker*","*.CryptoTorLocker2015!","*.cryptowall","*.cryptowin","*.CRYPTR","*.crypttt","*.CryptWalker","*.cryptx*","*.cryptz","*.crypz","*.CrySiS","*.cs16","*.cspider","*.CTB2","*.ctbl","*.CTBL2","*.ctrlalt@cock.li.district","*.cube","*.cxk_nmsl","*.cyberdrill","*.CYBERGOD","*.CyberSCCP","*.CyberSoldiersST","*.Cyclone","*.cypher","*.CYRON","*.czvxce","*.D2550A49BF52DFC23F2C013C5","*.d3g1d5","*.d4nk","*.da_vinci_code","*.DALE","*.dalle","*.damage","*.damoclis","*.danger","*.daris","*.DARKCRY","*.darkness","*.darus","*.DATA_IS_SAFE_YOU_NEED_TO_MAKE_THE_PAYMENT_IN_MAXIM_24_HOURS_OR_ALL_YOUR_FILES_WILL_BE_LOST_FOREVER_PLEASE_BE_REZONABLE_IS_NOT_A_JOKE_TIME_IS_LIMITED","*.DATASTOP","*.DATAWAIT","*.datun","*.david","*.davilarita@mail.com.yyy0","*.dcom","*.dcry","*.dCrypt","*.ddos","*.ddpcbi","*.decodeme666@tutanota_com","*.decodeme666tutanota_com","*.decrypt2017","*.decrypter@tutanota.com","*.decryptgarranty","*.decryptional","*.ded","*.dedo","*.deep","*.defender","*.DeLpHiMoRiX!@@@@_@@_@_2018_@@@_@_@_@@@","*.DeLpHiMoRiX*","*.demonslay335_you_cannot_decrypt_me!","*.deria","*.desu","*.DESYNC","*.DEUSCRYPT","*.DEXTER","*.dfjhsalfhsakljfhsljkahfdjklashfdjklh","*.DG","*.dharma","*.DHDR4","*.DIABLO6","*.dian","*.die","*.digiworldhack@tutanota.com","*.diller13","*.DiskDoctor","*.disposed2017","*.divine","*.djuvq","*.djvup","*.djvuq","*.djvur","*.djvus","*.djvut","*.Djvuu","*.dlenggrl","*.dmo","*.Do_not_change_the_file_name.cryp","*.DOCM!Sample","*.dodger","*.dodoc","*.dolphin","*.dom","*.domino","*.donation1@protonmail.ch.12345","*.donut","*.doomed","*.doples","*.dotmap","*.doubleoffset","*.Doxes","*.dqb","*.DQXOO","*.dragnea","*.DREAM","*.drume","*.drweb","*.DS335","*.ducueyuav","*.duhust","*.dutan","*.dviide","*.dwbiwty","*.dxjay","*.dxxd","*.dy8wud","*.dyaaghemy","*.dyatel@qq_com","*.e4m","*.ebay","*.ecc","*.eclr","*.eddldzor","*.edgel","*.EGG","*.eky","*.elpvd","*.EMAN","*.EMAN50","*.embrace","*.emilysupp","*.EMPTY","*.emsisosisoft","*.enc","*.enc_robbinhood","*.encedRSA","*.encencenc","*.EnCiPhErEd","*.encmywork","*.encoderpass","*.ENCR","*.encrptd","*.encrypt","*.Encrypted","*.encrypted.locked","*.Encrypted5","*.Encrypted[BaYuCheng@yeah.net].XiaBa","*.encrypted[Payfordecrypt@protonmail.com]","*.Encrypted_By_VMola.com","*.encryptedAES","*.encryptedALL","*.encryptedped","*.encryptedRSA","*.encryptedyourfiles","*.EncrypTile","*.enigma","*.enjey","*.Enter","*.EnyBenied","*.eoeo","*.epic","*.Epoblockl","*.eQTz","*.ERIS","*.ERIS!","*.ERROR","*.eTeRnItY","*.etols","*.euclid","*.EV","*.evil","*.evillock","*.evolution","*.evopro","*.excuses","*.executioner","*.exotic","*.ExpBoot","*.ExpBoot!","*.exploit","*.explorer","*.EXTE","*.extension.srpx","*.exx","*.EZDZ","*.ezz","*.ezzyl","*.f*cked","*.Facebook","*.FailedAccess","*.fairytail","*.fake","*.fantom","*.fartplz","*.fast","*.FASTBOB","*.fastrecovery.xmpp.jp","*.fastrecovery@airmail.cc","*.fastsupport@xmpp.jp","*.fat32","*.fbuvkngy","*.FCrypt","*.fedasot","*.ferosas","*.FEROSUS","*.FFF","*.File","*.file0locked","*.filegofprencrp","*.fileiscryptedhard","*.filesfucked","*.FileSlack","*.FilGZmsp","*.filock","*.fire","*.firecrypt","*.firmabilgileri","*.fix","*.FIXT","*.FJ7QvaR9VUmi","*.flat","*.FLATCHER3@INDIA.COM.000G","*.Flux","*.flyper","*.fmoon","*.forasom","*.fordan","*.format","*.fox","*.FREDD","*.freefoam","*.Freezing","*.frend","*.Frendi","*.Frivolity","*.frmvrlr2017","*.FRS","*.frtrss","*.fsdfsdfsdfsdfsdfsfdsfs","*.fuchsia","*.fuck","*.Fuck_You","*.fuck_you_av_we_are_not_globe_fake","*.fucked","*.FuckedByGhost","*.fucku","*.fuckyourdata","*.fun","*.FUNNY","*.G8xB","*.g^od","*.game","*.gamma","*.gangbang","*.gankLocked","*.garcewa","*.garrantydecrypt","*.gate","*.GBLOCK","*.gdb","*.GDCB","*.ge010gic","*.ge0l0gic","*.ge0l0gic_readme.txt","*.GEFEST","*.Gefest3","*.gefickt","*.gehad","*.gembok","*.gerber5","*.gero","*.gerosan","*.GETREKT","*.GG","*.GGGHJMNGFD","*.ghost","*.gigahertz","*.GILLETTE","*.globe","*.GMAN","*.GMBN","*.GMPF","*.gocr","*.godes","*.godra","*.goforhelp","*.gommemode","*.good","*.GORILLA","*.gotcha","*.GOTHAM","*.GOTYA","*.gr3g","*.GRANIT","*.granny","*.GrAnoSinSa","*.greystars@protonmail.com","*.GRHAN","*.gropas","*.grovas","*.grovat","*.grt","*.GrujaRS","*.grux","*.gruzin@qq_com","*.gryphon","*.GSupport3","*.guesswho","*.gui","*.gusau","*.guvara","*.gws","*.gws.porno","*.h3ll","*.H_F_D_locked","*.ha3","*.hac","*.hacked","*.hacked.by.Snaiparul","*.Hades666","*.Hades666!","*.haka","*.HakunaMatata","*.hannah","*.HAPP","*.happenencedfiles","*.happy","*.happydayzz","*.happyness","*.harma","*.Harzhuangzi","*.hasp","*.haters","*.hb15","*.hccapx","*.hceem","*.hcked","*.hdeaf","*.heets","*.heisenberg","*.HELLO","*.help24decrypt@qq.com","*.help_restore*.*","*.helpdecrypt@india.com","*.helpdecrypt@ukr*.net","*.helpdecrypt@ukr.net","*.helpdecrypt@ukr_net","*.helpmeencedfiles","*.helppme@india.com.*","*.HELPPME@INDIA.COM.ID83994902","*.herad","*.herbst","*.Hermes","*.Hermes666","*.HeroesOftheStorm","*.heroset","*.HHFEHIOL","*.hilegofprencrp","*.hitler","*.hjgdl","*.hncdumn","*.hNcrypt","*.hnumkhotep","*.hnumkhotep@india.com.hnumkhotep","*.hnyear","*.hofos","*.honor","*.horon","*.Horros","*.Horse4444","*.Horsuke","*.horsuke@nuke.africa","*.How_To_Decrypt.txt","*.How_To_Get_Back.txt","*.how_to_recover*.*","*.howcanihelpusir","*.HRM","*.hrosas","*.htrs","*.hush","*.HUSTONWEHAVEAPROBLEM@KEEMAIL.ME","*.hydracrypt_ID*","*.hydracrypt_ID_*","*.HYENA","*.I'WANT MONEY","*.iaufhhhfiles_BACK_PLS_READ.html","*.iaufhhhhfiles_BACK_PLS_READ.html","*.iaufkakfhsaraf","*.id-*.[*@*].*","*.id-*.cmb","*.id-02B52D6C.[Bas_ket@aol.com].java","*.id-3044989498_x3m","*.ID-7ES642406.CRY","*.id-XXXXX.[payday@tfwno.gf].html","*.id-XXXXXX.[btcdecoding@qq.com].dqb","*.id-xxxxxx.[mr.hacker@tutanota.com].USA","*.id-XXXXXXXX.[adm15@pr…","*.id-XXXXXXXX.[bitcoin1@foxmail.com].harma","*.id.*.crazy","*.id[********-1161].[member987@tutanota.com].actin","*.id[C4BA3647-2271].[worldofdonkeys@protonmail.com].BORISHORSE","*.id[RandomIP].[bron_lynn@aol.com].help","*.id[XXXXX-2275].[raynorzlol@tutanota.com].Adame","*.id[XXXXXX-1135].[walletwix@aol.com].actin!","*.id[XXXXXX-2300].[crysall.g@aol.com].banjo","*.id[XXXXXXX-XXXX].[wewillhelpyou@qq.com].adage!","*.id[XXXXXXXX-2242].[Ke…","*.id[XXXXXXXX-2275].[supportcrypt2019@cock…","*.id[XXXXXXXX-2275…","*.id_*********_.WECANHELP","*.id_XXXXXXX_.YOUR_LAST_CHANCE!","*.ifuckedyou","*.iGotYou","*.igza4c","*.ihsdj","*.ILLNEST","*.iloveworld","*.impect","*.improved","*.imsorry","*.INCANTO","*.incpas","*.INDRIK","*.infected","*.infileshop@gmail_com_ID44","*.Infinite","*.info","*.infovip@airmail.cc","*.INFOWAIT","*.insane","*.insta","*.invaded","*.Ipcrestore","*.ipygh","*.ironhead","*.isis","*.isolated","*.ispfv","*.israbye","*.ITLOCK","*.iudgkwv","*.IWANT","*.iwanthelpuuu","*.jack","*.jaff","*.JAMES","*.jamper","*.jcry","*.jeepdayz@india.com","*.JEEPERS","*.jes","*.jewsomware","*.jey","*.JezRoz","*.JFCWF","*.jimm","*.JKOUOGVG","*.JLCW2","*.jodis","*.josep","*.jse","*.jsworm","*.Jumper","*.jundmd@cock.li*","*.jungle@anonymousspechcom","*.junior","*.junked","*.jupstb","*.justbtcwillhelpyou","*.justice","*.jzphmsfs","*.k0stya","*.K8VfiZ","*.kali","*.KARLS","*.karne","*.katipuneros","*.katyusha","*.kcwenc","*.ke3q","*.kee","*.keepcalm","*.kencf","*.kernel_complete","*.kernel_pid","*.kernel_time","*.kes$","*.keybtc@inbox","*.keybtc@inbox_com","*.KEYH0LES","*.KEYHOLES","*.KEYPASS","*.KEYZ","*.KEYZ.KEYH0LES","*.kezoz","*.Kg9EX","*.kgpvwnr","*.KICK","*.kilit","*.kill","*.killedXXX","*.kimchenyn","*.kimcilware","*.kimcilware.locked","*.king_ouroboros*","*.Kiratos","*.kirked","*.kitty","*.kjh","*.KK","*.kkk","*.klope","*.kok","*.KOK08","*.KOK8","*.korea","*.koreaGame","*.korrektor","*.kostya","*.kovasoh","*.kr3","*.KRAB","*.kraken","*.kratos","*.kraussmfz","*.kropun","*.kroput","*.kroput1","*.krusop","*.krypted","*.kryptonite","*.krzffw","*.ktuhzxpi","*.KUAJW","*.kuntzware","*.kvllyatprotonmaildotch","*.kwaaklocked","*.kyra","*.L0CKED","*.L1LL","*.lalabitch","*.lalabitch,","*.lambda.l0cked","*.LAMBDA.LOCKED","*.lambda_l0cked","*.lamo","*.langolier","*.LanRan*","*.LanRan2.0.5","*.lanset","*.lapoi","*.Lazarus","*.lbiaf6c8","*.LCKD","*.lcked","*.lcphr","*.lcphr!Ransom","*.LDPR","*.LeChiffre","*.leen","*.leenapidx","*.leenapidx@snakebite.com.hrhr","*.legacy","*.legion","*.LEGO","*.leon","*.les#","*.lesli","*.letmetrydecfiles","*.lfk","*.LGAWPULM","*.libbywovas@dr.com.gr3g","*.LIGHTNING","*.like","*.lilocked","*.limbo","*.lime","*.LIN","*.litar","*.litra","*.litra!Sample","*.LOCK75","*.lock93","*.lockd","*.locked","*.locked-*","*.Locked-by-Mafia","*.LOCKED.txt","*.locked.zip","*.locked3","*.locked_by_mR_Anonymous(TZ_HACKERS)","*.LOCKED_BY_pablukl0cker","*.Locked_file","*.lockedfile","*.lockedgood","*.locker","*.lockhelp@qq.gate","*.Lockify","*.locklock","*.lockme","*.LOCKOUT","*.locky","*.lockymap","*.lokas","*.lokitus","*.lol","*.LOL!","*.LOLI","*.lolita","*.LolSec","*.londec","*.loptr","*.lordofshadow","*.Losers","*.lost","*.lotej","*.lotep","*.LOVE","*.loveransisgood","*.lovewindows","*.LoveYou","*.loveyouisreal","*.LTML","*.luboversova148","*.luceq","*.luces","*.lucky","*.lukitus","*.lukitus-tiedostopäätettä","*.lurk","*.madebyadam","*.madek","*.madekv120","*.mafee","*.magic","*.magic_software_syndicate","*.major","*.makkonahi","*.maktub","*.Malki","*.malwarehunterteam","*.mamasitaq","*.mamba","*.mammon","*.maniac","*.mariacbc","*.Marozka","*.mars","*.masodas","*.masok","*.master","*.MATRIX","*.maxicrypt","*.MAYA","*.maysomware","*.mbrcodes","*.Mcafee","*.MDEN","*.mdk4y","*.MDRL","*.mecury","*.medal","*.megac0rtx","*.megacortex","*.mention9823","*.Mercury","*.MERRY","*.mers","*.messenger-*","*.metan","*.mich","*.micro","*.middleman2020","*.MIKOYAN","*.mind","*.Mira","*.MMM","*.mo7n","*.mogera","*.mogranos","*.MOLE","*.MOLE00","*.MOLE01","*.MOLE02","*.MOLE03","*.MOLE04","*.MOLE66","*.moments2900","*.monro","*.mordor","*.moresa","*.mouse","*.MRCR1","*.ms13","*.msj","*.MTC","*.mtk118","*.mtogas","*.MTXLOCK","*.muslat","*.mvp","*.MyChemicalRomance4EVER","*.myjob","*.myransext2017","*.myskle","*.n7ys81w","*.nacro","*.nalog@qq_com","*.Nano","*.napoleon","*.nasoh","*.Navi","*.nazcrypt","*.ndarod","*.ndpyhss","*.needdecrypt","*.needkeys","*.neitrino","*.nelasod","*.nemesis","*.nemo-hacks.at.sigaint.org","*.nemty","*.Neptune","*.neras","*.netn6","*.NEWRAR","*.news","*.NGSC","*.NHCR","*.NIGGA","*.NM4","*.NMCRYPT","*.no_more_ransom","*.no_more_ransomware","*.NOBAD","*.noblis","*.nochance","*.Node0","*.NOLOST","*.non","*.NOOB","*.nopasaran","*.noproblemwedecfiles","*.norvas","*.nosafe","*.nostro","*.NOT","*.NOT_OPEN","*.notfoundrans","*.novasof","*.Novosof","*.nozelesn","*.nsmf","*.ntu","*.ntuseg","*.nuclear","*.nuclear55","*.nuke55","*.nuksus","*.NUMBERDOT","*.nusar","*.Nutella","*.nvetud","*.nWcrypt","*.o$l","*.O67NG","*.obagarmrk","*.ObcKIn","*.obfuscated","*.OBLIVION","*.ocean","*.odcodc","*.odin","*.OGONIA","*.ogre","*.OhNo!","*.okean*","*.okokokokok","*.olduw","*.oled","*.omerta","*.OMG!","*.one","*.one-we_can-help_you","*.oneway","*.oni","*.ONION","*.online24files@airmail.cc","*.onlinesupport","*.only-we_can-help_you","*.ONYC","*.onyon","*.ONYX","*.OOFNIK","*.OOOKJYHCTVDF","*.oops","*.oor","*.open_readme.txt.ke3q","*.openforyou@india.com","*.oplata@qq_com","*.OQn1B","*.Ordinal","*.orion","*.oshit","*.osiris","*.osk","*.oslawcmme","*.otherinformation","*.OTR","*.owned","*.Ox4444","*.OXR","*.p5tkjw","*.PA-SIEM","*.pablukCRYPT","*.pabluklocker","*.padcrypt","*.PANDA","*.parrot","*.partially.cryptojoker","*.partially.cryptoNar","*.PAUSA","*.PAY","*.pay2me","*.PAY_IN_MAXIM_24_HOURS_OR_ALL_YOUR_FILES_WILL_BE_PERMANENTLY_DELETED_PLEASE_BE_REZONABLE_you_have_only_1_single_chance_to_make_the_payment","*.paybtcs","*.paycoin","*.paycyka","*.PayDay","*.payfordecrypt","*.payfornature@india.com.crypted","*.payforunlock","*.paym","*.paymds","*.paymrss","*.paymrts","*.payms","*.paymst","*.paymts","*.payransom","*.payrms","*.pays","*.paytounlock","*.PC-FunHACKED*","*.pdcr","*.pdf.p3rf0rmr","*.pdf_Axffyq_{babyfromparadise666@gmail.com}.p3rf0rm4","*.pdff","*.PEDANT","*.PEDO","*.pedro","*.PEGS1","*.pennywise","*.peosajwqfk","*.Persephone666!","*.PERSONAL_ID*","*.Petya","*.pfanz","*.phantom","*.PHOBOS","*.phoenix","*.PICO","*.pidom","*.pidon","*.Pig4444","*.PIRATE","*.pizda@qq_com","*.pizdec","*.pizdosik","*.pky","*.PLANETARY","*.PLANT","*.plauge17","*.pleaseCallQQ","*.PLIN","*.PLUT","*.pluto","*.pnr","*.PoAr2w","*.POHU","*.poof","*.poolezoor","*.poop","*.popotic","*.popoticus","*.porno","*.porno.pornoransom","*.pornoransom","*.POSHKODER","*.potato","*.powerfuldecrypt","*.powerfulldecrypt","*.powned","*.Pox","*.poyvonm","*.ppam","*.pr0tect","*.Prandel","*.PRCP","*.predator","*.PRIVAT66","*.Prodecryptor","*.proden","*.promock","*.promorad","*.promorad2","*.promos","*.promoz","*.prosperous666","*.PrOtOnIs","*.PrOtOnIs.VaNdElIs","*.prus","*.pscrypt","*.psh","*.PTGEPVEKM","*.pulsar1","*.Puma","*.pumas","*.PUMAX","*.purge","*.pwned","*.pzdc","*.qbix","*.qbtex","*.QH24","*.qnbqw","*.qq_com*","*.Qtyu8vH5wDXf6OSWAm5NuA==ObcK","*.qwerty","*.qweuirtksd","*.qwex","*.qwqd","*.R.i.P","*.R16M01D05","*.R3K7M9","*.r3store","*.R4A","*.R4bb0l0ck","*.R5A","*.RaaS","*.RAD","*.RADAMANT","*.radman","*.raid10","*.raldug","*.ram","*.ramen","*.rand","*.ranranranran","*.ranrans","*.Ransed","*.RANSOM","*.RansomAES","*.ransomcrypt","*.ransomed@india.com","*.RansomMine","*.ransomwared","*.rapid","*.RARE1","*.RASTAKHIZ","*.rat","*.razarac","*.razy","*.razy1337","*.rcrypted","*.RDM","*.rdmk","*.RDWF","*.Read_Me.Txt","*.read_to_txt_file.yyto","*.readme_txt","*.reaGAN","*.realfs0ciety*","*.realfs0ciety@sigaint.org.fs0ciety","*.REBUS","*.recme","*.recovery_email_[retmydata@protonmail.com]*.aes256","*.recovery_email__retmydata@protonmail.com__*_.aes256.testE","*.RECOVERYOURFILES","*.recry1","*.rectot","*.RedEye","*.redmat","*.refols","*.rekt","*.relock@qq_com","*.remind","*.rencrypted","*.RENSENWARE","*.rent","*.restore_fi*.*","*.resurrection","*.REVENGE","*.revolution","*.reycarnasi1983@protonmail.com.gw3w","*.Reyptson","*.rezuc","*.rip","*.risk","*.rjzR8","*.RJZUNA","*.RMCM1","*.rnsmwr","*.rnsmwre","*.robbinhood","*.robinhood","*.rokku","*.roland","*.roldat","*.rontok","*.rose","*.rpd","*.RRK","*.rsalive","*.RSNSlocked","*.RSplited","*.rsucozxze","*.rtyrtyrty","*.rumba","*.rumblegoodboy","*.ryk","*.ryp","*.Ryuk","*.ryx","*.s1crypt","*.sage","*.SaherBlueEagleRansomware","*.SALSA222","*.sambo","*.sambo,","*.same","*.SaMsUnG","*.sanction","*.SANTANA","*.sarut","*.satan","*.SATANA","*.saturn","*.Satyr","*.SAVEfiles","*.SAVEYOURDATA","*.SBLOCK","*.scarab","*.scl","*.scorpio","*.Scorpion","*.SDEN","*.sdk","*.sdwwbrb","*.sea","*.secure","*.SecureCrypte","*.SecureCrypted","*.securityP","*.seed","*.SENRUS17","*.SEPSIS","*.SERP","*.serpent","*.Server","*.setimichas1971@protonmail.com.b4wq","*.SEVENDAYS","*.sexy","*.SF","*.sfs","*.sgood","*.sguard","*.shadi","*.shadow","*.SHARK","*.shelbyboom","*.shifr","*.shinigami","*.shino","*.shit","*.SHRUG","*.SHRUG2","*.shutdown57","*.ShutUpAndDance","*.sifreli","*.sigrun","*.Sil3nt5pring","*.Silent","*.sinopal","*.sinta","*.si…","*.sjjpu","*.SKJDTHGHH","*.skunk","*.skvtb","*.sky","*.skymap","*.skype","*.SKYSTARS","*.SLAV","*.slvpawned","*.snake","*.snake4444","*.snatch","*.SOLO","*.son","*.SONIC","*.sophos","*.sorry","*.spaß","*.SPCT","*.spectre","*.spider","*.spora","*.sport","*.spyhunter","*.Srpx","*.ssananunak1987@protonmail.com.b2fr","*.sshxkej","*.ssimpotashka@gmail.com","*.stare","*.stevenseagal@airmail.cc","*.Stinger","*.stn","*.stone","*.STOP","*.stroman","*.stun","*.styver","*.styx","*.suffer","*.SUPERCRYPT","*.supported2017","*.supportfiless24@protonmail.ch","*.suppose666","*.surprise","*.SUSPENDED","*.sux","*.sux.AES128","*.sVn","*.switch","*.symbiom_ransomware_locked","*.SYMMYWARE","*.syrk","*.sysdown","*.szesnl","*.szf","*.TABGH","*.tabufa","*.TaRoNiS","*.tastylock","*.tater","*.tax","*.technicy","*.tedcrypt","*.telebak","*.Tesla","*.TEST","*.tfude","*.Tfudeq","*.tfudet","*.TGIF","*.THANATOS","*.THDA","*.TheTrumpLockerf","*.TheTrumpLockerp","*.theva","*.theworldisyours","*.thor","*.thunder","*.Tiger4444","*.tmp.exe","*.to.dernesatiko@mail.com.crypted","*.todar","*.todarius","*.tokog","*.Tornado","*.toxcrypt","*.TraNs","*.trevinomason1@mail.com.vsunit","*.triple_m","*.TRMT","*.tro","*.TROLL","*.TROLL,","*.tron","*.tronas","*.trosak","*.troyancoder@qq_com","*.TRUE","*.truke","*.trump","*.trun","*.tsv","*.ttt","*.tuki17@qq.com","*.tunca","*.twist","*.tzu","*.ucftz*","*.udjvu","*.uDz2j8mv","*.UIK1J","*.UIWIX","*.uk-dealer@sigaint.org","*.UKCZA","*.ukr.net*","*.ukrain","*.unavailable","*.unbrecrypt_ID_*","*.UNIT09","*.UNLIS","*.upd9ykc65v","*.UselessFiles","*.usr0","*.uudjvu","*.vaca","*.vally","*.vanss","*.Vapor","*.vault","*.VBRANSOM","*.vCrypt1","*.vdul","*.velikasrbija","*.velso","*.VENDETTA","*.vendetta2","*.Venusf","*.venusp","*.verasto","*.vesad","*.vesrato","*.VforVendetta","*.via","*.viiper","*.viki","*.vindows","*.VisionCrypt","*.volcano","*.vpgvlkb","*.vrmrkz","*.vscrypt","*.vulston","*.vusad","*.vvv","*.vxLock","*.W0YR8","*.wal","*.WALAN","*.WALAN,","*.wallet","*.WAmarlocked","*.Wana Decrypt0r Trojan-Syria Editi0n","*.WAND","*.wannacash","*.wannacryv2","*.warn_wallet","*.wav_list","*.wcry","*.WCRYT","*.wdie","*.weapologize","*.weareyourfriends","*.weencedufiles","*.wewillhelp@airmail.cc","*.wflx","*.whatthefuck","*.Where_my_files.txt","*.Whereisyourfiles","*.WHY","*.whycry","*.WHY…","*.wincry","*.WINDOWS","*.windows10","*.wlu","*.wmfxdqz","*.wncry","*.wncrypt","*.wncryt","*.wndie","*.wnry","*.wooly","*.Work","*.WORMCRYPT0R","*.WORMKILLER@INDIA.COM.XTBL","*.wowreadfordecry","*.wowreadfordecryp","*.wowwhereismyfiles","*.write","*.write_on_email","*.write_us_on_email","*.WRNY","*.wsmile","*.wtdi","*.wtf","*.wuciwug","*.WWW","*.Wx7A6","*.wxdrJbgSDa","*.wyvern","*.x0lzs3c","*.x1881","*.x3m","*.x3mpro","*.XBTL","*.Xcri","*.xcry7684","*.xcrypt","*.xdata","*.XERO","*.xfile","*.xhspythxn","*.XiaoBa","*.XiaoBa1","*.xiaoba10","*.xiaoba11","*.xiaoba12","*.xiaoba13","*.xiaoba14","*.xiaoba15","*.xiaoba16","*.xiaoba17","*.xiaoba18","*.xiaoba19","*.xiaoba2","*.xiaoba20","*.xiaoba21","*.xiaoba22","*.xiaoba23","*.xiaoba24","*.xiaoba25","*.xiaoba26","*.xiaoba27","*.xiaoba28","*.xiaoba29","*.xiaoba3","*.xiaoba30","*.xiaoba31","*.xiaoba32","*.xiaoba33","*.XiaoBa34","*.xiaoba4","*.xiaoba5","*.xiaoba6","*.xiaoba7","*.xiaoba8","*.xiaoba9","*.XmdXtazX","*.XmdXtazX.","*.xncrypt","*.xolzsec","*.xorist","*.xort","*.XRNT","*.xrtn","*.xtbl","*.xuy","*.XVNAW","*.xwz","*.xxx","*.xxxxx","*.XY6LR","*.xyz","*.xz","*.XZZX","*.Yakes","*.yatron","*.YAYA","*.yG","*.YIAQDG","*.ykcol","*.yl","*.yoewy","*.YOLO","*.YOU-ARE-FUCKED-BY-BALILUWARE-(CODED-BY-HEROPOINT)","*.YOUR_LAST_CHANCE","*.youransom","*.yourransom","*.YTBL","*.yum","*.YYTO","*.YYYYBJQOQDU","*.z3r0","*.Z81928819","*.ZABLOKOWANE","*.zatrov","*.ZAYKA","*.zbt","*.zc3791","*.zcrypt","*.zendr4","*.zepto","*.zilla","*.Zimbra","*.ZINO","*.ziqzqzdi","*.zlpzdel","*.zoh","*.zoro","*.zorro","*.ztsysjz","*.zuzya","*.ZW","*.zXz","*.zycrypt","*.zyklon","*.zypto*","*.zzz","*.zzz12","*.Zzzz","*.zzzzz","*.zzzzzzzz","*.{25BF1879-A2DC-B66A-3CCC-XXXXXXXXXXXX}","*.{CALLMEGOAT@PROTONMAIL.COM}CMG","*.{CRYPTENDBLACKDC}","*.{Help557@gmx.de}.exe","*.{incredible0ansha@tuta.io}.ARA","*.{Killback@protonmail.com}KBK","*.{ljspqk7@aol.com}.BRT92","*.{mattpear@protonmail.com}","*.{mattpear@protonmail.com}MTP","*.{saruman7@india.com}.BRT92","*.{XXXXX-EFEE-6C04-D2DC-A9EFA812DD11}!","*.{XXXXXXX-588E-7D5B-AED1-2CD51808DE12}","*.~HL*","*.~xdata~","*.Защищено","*.инструкция по оплате.txt","*.кибер разветвитель","*.已加密","*.干物妹！","*.암호화됨","*0nl1ne*","*@*.blocking","*@adsoleware.com*","*@cock.email","*@cumallover.me*","*@gmail_com_*","*@india.com*","*@LOCKED","*@tuta.io]","*@tutanota.com]","*[Beamsell@qq.com].bip","*[cryptservice@inbox.ru]*","*[cryptsvc@mail.ru].*","*[decryptdata@qq.com].rar","*[files.restore@aol.com].write","*[gomer_simpson2@aol.com].phobos","*[ignatevv330@gmail.com].java","*[java2018@tuta io].arrow","*[lavandos@dr.com].wallet","*[p4d@tuta.io].com","*[qmqtt@protonmail.ch].HRM","*[qrrqtt@protonmail.ch].HRM","*[RELOCK001@TUTA.IO]","*[remarkpaul77@cock.li].JSWORM","*[shivamana@seznam.cz].pip","*].block","*_.rmd","*_[LINERSMIK@NAVER.COM][JINNYG@TUTANOTA","*__{}.VACv2","*_crypt","*_help_instruct*.*","*_HELP_instructions.html","*_HOWDO_text.bmp","*_HOWDO_text.html","*_luck","*_nullbyte*","*_READ_THIS_FILE_*_*","*_recover_*.*","*_ryp","*_steaveiwalker@india.com_","*_WHAT_is.html","*adobe.gefest","*aes_ni_gov","*bingo@opensourcemail.org","*BlockBax*","*cerber2","*decipher*","*decrypt my file*.*","*decrypt your file*.*","*decryptmyfiles*.*","*Decryptoroperator@qq.com","*djvuu","*drakosho_new@aol.com*","*EdgeLocker*.exe","*files_are_encrypted.*","*fuga139gh@dr.com*","*garryweber@protonmail.ch","*gmail*.crypt","*help_restore*.*","*HERMES","*How to Decrypt Files-*.html","*how_to_recover*.*","*id-*.BI_ID","*id-*_[*@*.*].*","*id-.LyaS","*info@kraken.cc_worldcza@email.cz","*install_tor*.*","*keemail.me*","*king_ouroboros*","*lockhelp@qq.com","*maestro@pizzacrypts.info","*opentoyou@india.com","*qq_com*","*ReadMe_Decryptor.txt","*rec0ver*.*","*recover_instruction*.*","*recover}-*.*","*restore_fi*.*","*RT4BLOCK","*SIMMYWARE*","*snowpicnic*","*ukr.net*","*wall.i","*want your files back.*","*warning-!!*.*","*ymayka-email@yahoo.com.cryptotes","*zn2016","*{alexbanan@tuta.io}.CORP","---README---.TXT",". vesrato","..g.","..luceq",".0x0",".1999",".1txt",".31392E30362E32303136_[*]_LSBJ1",".6vr378txi",".73i87A",".777",".7h9r",".8lock8",".[*].blt",".[*].encrypted",".[*].globe",".[*].raid10",".[*]_luck",".[decryptor@cock.li].dcrtr",".[mia.kokers@aol.com]",".[ogorman.linoel@aol.com].help",".[ti_kozel@lashbania.tv].*",".___xratteamLucked",".__AiraCropEncrypted!","._AiraCropEncrypted",".a19",".aaa",".abc",".adk",".adobe",".adobee",".adr",".aes",".AES256",".aesir",".AFD",".aga",".Alcatraz",".amba",".angelamerkel",".AngleWare",".antihacker2017",".ap19",".axx",".BarRax",".bart",".bart.zip",".berost",".besub",".better_call_saul",".bin",".bip",".bitstak",".bleep",".bleepYourFiles",".bloc",".blocatto",".blower",".boston",".braincrypt",".breaking_bad",".bript",".browec",".btc",".btc-help-you",".btcbtcbtc",".btcware",".bufas",".bxtyunh",".cbf",".ccc",".CCCRRRPPP",".cerber",".cerber2",".cerber3",".cezor",".charck",".charcl",".chech",".chifrator@qq_com",".CHIP",".cifgksaffsfyghd",".clf",".code",".coded",".codnat",".codnat1",".comrade",".CONTACTUS",".coverton",".crashed",".crime",".crinf",".criptiko",".criptoko",".criptokod",".cripttt",".crjoker",".crptrgr",".crptxxx",".CRRRT",".cry",".cry_",".cryp1",".crypt",".crypt*",".crypt38",".crypted",".crypted_file",".crypto",".cryptolocker",".CRYPTOSHIEL",".CRYPTOSHIELD",".CryptoTorLocker2015!",".crypttt",".cryptz*",".crypz",".CrySiS",".css",".CTB2",".CTBL",".ctbl",".czvxce",".d4nk",".da_vinci_code",".DALE",".dalle",".damage",".darkness",".DATASTOP",".DATAWAIT",".davda",".dCrypt",".decrypt2017",".ded",".deria",".devil",".DHARMA",".dharma",".DIABLO6",".disappeared",".djvu",".djvuq",".djvur",".djvus",".djvut",".djvuu",".Do_not_change_the_filename",".domino",".doomed",".doples",".dotmap",".drume",".dutan",".dxxd",".dyatel@qq_com _ryp",".ecc",".edgel",".ENC",".enc",".encedRSA",".EnCiPhErEd",".encmywork",".encoderpass",".ENCR",".encrypt",".encrypted",".ENCRYPTED",".EnCrYpTeD",".Encrypted",".encrypted ",".ENCRYPTED_BY_LLTP",".ENCRYPTED_BY_LLTPp",".encryptedAES",".encryptedRSA",".encryptedyourfiles",".enigma",".epic",".eth",".etols",".evillock",".exotic",".exx",".ezz",".fantom",".fear",".fedasot",".FenixIloveyou!!",".ferosas",".file0locked",".fileiscryptedhard",".filock",".firecrypt",".forasom",".fordan",".frtrss",".fs0ciety",".fuck",".fucked",".FuckYourData",".fun",".gefickt",".gerosan",".good",".grovas",".grovat",".grt",".gruzin@qq_com",".guvara",".gws",".H3LL",".h3ll",".HA3",".ha3",".hannah",".hb15",".helpdecrypt@ukr.net",".helpmeencedfiles",".herbst",".heroset",".hnumkhotep",".hofos",".horon",".hrosas",".html",".hush",".iaufkakfhsaraf",".id-*.[*@*].air",".id-*.cry",".id-*_help@decryptservice.info",".id-[*]-maestro@pizzacrypts.info",".id-_CarlosBoltehero@india.com_",".id-_garryweber@protonmail.ch",".id-_julia.crown@india.com_",".id-_locked",".id-_locked_by_krec",".id-_locked_by_perfect",".id-_maria.lopez1@india.com_",".id-_r9oj",".id-_steaveiwalker@india.com_",".id-_tom.cruz@india.com_",".id-_x3m",".iloveworld",".infected",".INFOWAIT",".isis",".iwanthelpuuu",".jack",".justbtcwillhelpyou",".KARLOS",".karma",".kencf",".keybtc@inbox_com",".KEYH0LES",".KEYPASS",".KEYZ",".killed*",".kimcilware",".kiratos",".Kirked",".kkk",".klope",".korrektor",".kostya",".kr3",".kraken",".kratos",".kropun",".kroput",".kroput1",".L0CKED",".L0cked",".lambda_l0cked",".lanset",".LeChiffre",".lesli",".letmetrydecfiles",".Licked",".litar",".lock",".lock93",".Locked",".locked",".locked-[*]",".Locked-by-Mafia",".locklock",".locky",".lokas",".LOL!",".lotep",".lovewindows",".luces",".lukitus",".madebyadam",".magic",".maktub",".megac0rtx",".MERRY",".micro",".MKJL",".mogera",".mole",".mole02",".moresa",".MRCR1",".muslat",".myskle",".nalog@qq_com",".nampohyu",".neitrino",".nemo-hacks.at.sigaint.org",".neras",".no_more_ransom",".nochance",".noproblemwedecfiles",".norvas",".notfoundrans",".nuclear55",".nusar",".odcodc",".odin",".OMG!",".OMG*",".only-we_can-help_you",".oops",".openforyou@india.com",".oplata@qq_com",".oshit",".osiris",".otherinformation",".p5tkjw",".padcrypt",".PAUSA",".paybtcs",".payms",".paymst",".payransom",".payrmts",".paytounlock",".pdff",".PEGS1",".phobos",".pidon",".pizda@qq_com",".PLAUGE17",".plomb",".PLUT",".PoAr2w",".poret",".porno",".potato",".powerfulldecrypt",".proden",".promock",".promok",".promoks",".promorad",".promorad2",".promos",".promoz",".protected",".pulsar1",".puma",".pumas",".pumax",".purge",".pzdc",".PzZs",".R.i.P",".R16M01D05",".R4A",".R5A",".r5a",".RAD",".RADAMANT",".radman",".raldug",".RARE1",".razy",".RDM",".rdmk",".rectot",".redmat",".refols",".rekt",".relock@qq_com",".remind",".rescuers@india.com.3392cYAn548QZeUf.lock",".REVENGE",".rezuc",".rip",".RMCM1",".rmd",".rnsmwr",".rokku",".roland",".roldat",".RRK",".RSNSlocked",".RSplited",".rumba",".sage",".sanction",".sarut",".SAVEfiles",".scarab",".scl",".SecureCrypted",".serpent",".sexy",".shadow",".shino",".shit",".sifreli",".Silent",".skymap",".sport",".stn",".stone",".STOP",".STOPDATA",".SUPERCRYPT",".surprise",".SUSPENDED",".szf",".tfude",".tfudeq",".tfudet",".TheTrumpLockerf",".TheTrumpLockerfp",".theworldisyours",".thor",".todarius",".toxcrypt",".tro",".tronas",".trosak",".troyancoder@qq_com",".truke",".trun",".ttt",".tzu",".udjvu",".uk-dealer@sigaint.org",".unavailable",".unlockvt@india.com",".uudjvu",".vault",".VBRANSOM",".velikasrbija",".Venusf",".Venusp",".verasto",".versiegelt",".VforVendetta",".vindows",".vscrypt",".vvv",".vxLock",".WAITING",".wallet",".WCRY",".wcry",".weareyourfriends",".weencedufiles",".wflx",".Where_my_files.txt",".Whereisyourfiles",".WHY",".windows10",".WNCRY",".wncry",".wnx",".xcri",".xcrypt",".xort",".XRNT",".xrtn",".XTBL",".xtbl",".XXX",".xxx",".xyz",".yourransom",".Z81928819",".zc3791",".zcrypt",".zepto",".zerofucks",".ZINO",".zorro",".zXz",".zyklon",".zzz",".zzzzz",".{CRYPTENDBLACKDC}",".~",".~xdata~",".кибер разветвитель",".已加密","000-IF-YOU-WANT-DEC-FILES.html","000-No-PROBLEM-WE-DEC-FILES.html","000-PLEASE-READ-WE-HELP.html","0000-SORRY-FOR-FILES.html","001-READ-FOR-DECRYPT-FILES.html","005-DO-YOU-WANT-FILES.html","009-READ-FOR-DECCCC-FILESSS.html","027cc450ef5f8c5f653329641ec1fed9*.*","0_HELP_DECRYPT_FILES.HTM","170fb7438316.exe","4-14-2016-INFECTION.TXT","52036F92.tmp","686l0tek69-HOW-TO-DECRYPT.txt","@_RESTORE-FILES_@.*","@_USE_TO_FIX_*.txt","@decrypt_your_files.txt","@Please_Read_Me@.txt","@WanaDecryptor@.*","@WARNING_FILES_ARE_ENCRYPTED.*.txt","[*]-HOW-TO-DECRYPT.txt","[amanda_sofost@india.com].wallet","[KASISKI]","[KASISKI]*","[Lockhelp@qq.com].Gate","_!!!_README_!!!_*","_!!!_README_!!!_*_ .txt","_!!!_README_!!!_*_.hta","_*_HOWDO_text.html","_*_README.hta","_*_README.jpg","_Adatok_visszaallitasahoz_utasitasok.txt","_crypt","_CRYPTED_README.html","_DECRYPT_INFO_*.html","_DECRYPT_INFO_szesnl.html","_H_e_l_p_RECOVER_INSTRUCTIONS*.html","_H_e_l_p_RECOVER_INSTRUCTIONS*.png","_H_e_l_p_RECOVER_INSTRUCTIONS*.txt","_H_e_l_p_RECOVER_INSTRUCTIONS+*.html","_H_e_l_p_RECOVER_INSTRUCTIONS+*.png","_H_e_l_p_RECOVER_INSTRUCTIONS+*.txt","_HELP_HELP_HELP_*","_HELP_HELP_HELP_*.hta","_HELP_HELP_HELP_*.jpg","_help_instruct*.*","_HELP_INSTRUCTION.TXT","_HELP_instructions.bmp","_HELP_instructions.txt","_HELP_INSTRUCTIONS_.TXT","_HELP_Recover_Files_.html","_How to restore files.*","_how_recover*.html","_how_recover*.txt","_how_recover+*.html","_how_recover+*.txt","_how_recover.txt","_HOW_TO_Decrypt.bmp","_How_To_Decrypt_My_File_.*","_HOWDO_text.html","_INTERESTING_INFORMACION_FOR_DECRYPT.TXT","_iWasHere.txt","_Locky_recover_instructions.bmp","_Locky_recover_instructions.txt","_nullbyte","_READ_ME_FOR_DECRYPT.txt","_READ_THI$_FILE_*","_README_*.hta","_README_.hta","_RECOVER_INSTRUCTIONS.ini","_RECoVERY_+*.*","_RESTORE FILES_.txt","_ryp","_secret_code.txt","_WHAT_is.html","_XiaoBa_Info_.hta","_如何解密我的文件_.txt","AArI.jpg","About_Files.txt","aboutYourFiles.*","Aescrypt.exe","allcry_upx.exe","AllFilesAreLocked*.bmp","anatova.exe","anatova.txt","ASSISTANCE_IN_RECOVERY.txt","ATLAS_FILES.txt","ATTENTION!!!.txt","ATTENTION.url","bahij2@india.com","BitCryptorFileList.txt","Blooper.exe","BTC_DECRYPT_FILES.txt","BUYUNLOCKCODE","BUYUNLOCKCODE.txt","C-email-*-*.odcodc","CallOfCthulhu.exe","ClopReadMe.txt","cmdRansomware.*","Coin.Locker.txt","COME_RIPRISTINARE_I_FILE.*","Comment débloquer mes fichiers.txt","Como descriptografar seus arquivos.txt","COMO_ABRIR_ARQUIVOS.txt","COMO_RESTAURAR_ARCHIVOS.html","COMO_RESTAURAR_ARCHIVOS.txt","confirmation.key","crjoker.html","cryptinfo.txt","CRYPTOID_*","cryptolocker.*","CryptoRansomware.exe","Crytp0l0cker.dll","Crytp0l0cker.exe","Crytp0l0cker.Upack.dll","cscc.dat","Cversions.2.db","Cyber SpLiTTer Vbs.exe","DALE_FILES.TXT","damage@india.com*","de_crypt_readme.*","de_crypt_readme.bmp","de_crypt_readme.html","de_crypt_readme.txt","decipher_ne@outlook.com*","Decoding help.hta","Decrypt All Files *.bmp","decrypt all files*.bmp*","decrypt explanations.html","DECRYPT-FILES.html","decrypt-instruct*.*","decrypt_Globe*.exe","DECRYPT_INFO.txt","DECRYPT_INFORMATION.html","decrypt_instruct*.*","DECRYPT_INSTRUCTION.HTML","DECRYPT_INSTRUCTION.TXT","DECRYPT_INSTRUCTION.URL","DECRYPT_INSTRUCTIONS.html","DECRYPT_INSTRUCTIONS.TXT","DECRYPT_ReadMe.TXT","DECRYPT_Readme.TXT.ReadMe","DECRYPT_ReadMe1.TXT","DECRYPT_YOUR_FILES.HTML","DECRYPT_YOUR_FILES.txt","DecryptAllFiles*.txt","DecryptAllFiles.txt","decrypted_files.dat","DecryptFile.txt","DECRYPTION INSTRUCTIONS.txt","DECRYPTION.TXT","DECRYPTION_HOWTO.Notepad","Decryptyourdata@qq.com","decypt_your_files.html","default32643264.bmp","default432643264.jpg","DESIFROVANI_POKYNY.html","DesktopOsiris.*","DesktopOsiris.htm","diablo6-*.htm","dispci.exe","dllhost.dat","DOSYALARINIZA ULAŞMAK İÇİN AÇINIZ.html","dummy_file.encrypted","ebay-msg.html","ebay_was_here","email-salazar_slytherin10@yahoo.com.ver-*.id-*-*.randomname-*","email-vpupkin3@aol.com*","EMAIL_*_recipient.zip","enc_files.txt","ENCRYPTED.TXT","encryptor_raas_readme_liesmich.txt","enigma.hta","enigma_encr.txt","ENTSCHLUSSELN_HINWEISE.html","exit.hhr.obleep","fattura_*.js","FE04.tmp","File Decrypt Help.html","file0locked.js","File_Encryption_Notice.txt","Files encrypted.html","FILES ENCRYPTED.txt","FILES.TXT","FILES_BACK.txt","FILESAREGONE.TXT","filesinfo.txt","firstransomware.exe","Galaperidol.exe","GetYouFiles.txt","GJENOPPRETTING_AV_FILER.html","GJENOPPRETTING_AV_FILER.txt","GNNCRY_Readme.txt","Hacked_Read_me_to_decrypt_files.html","Hello There! Fellow @kee User!.txt","HELLOTHERE.TXT","Help Decrypt.html","help-file-decrypt.enc","HELP-ME-ENCED-FILES.html","HELP_BY_CROC.TXT","help_decrypt*.*","HELP_DECRYPT.HTML","HELP_DECRYPT.HTML*","HELP_DECRYPT.lnk","HELP_DECRYPT.PNG","Help_Decrypt.txt","HELP_DECRYPT.URL","help_decrypt_your_files.html","help_file_*.*","help_instructions.*","HELP_ME_PLEASE.txt","help_recover*.*","HELP_RECOVER_FILES.txt","help_recover_instructions*.bmp","help_recover_instructions*.html","help_recover_instructions*.txt","help_recover_instructions+*.BMP","help_recover_instructions+*.html","help_recover_instructions+*.txt","help_restore*.*","HELP_RESTORE_FILES.txt","HELP_RESTORE_FILES_*.*","HELP_RESTORE_FILES_*.TXT","help_to_decrypt.txt","HELP_TO_DECRYPT_YOUR_FILES.txt","HELP_TO_SAVE_FILES.bmp","HELP_TO_SAVE_FILES.txt","help_your_file*.*","HELP_YOUR_FILES.html","HELP_YOUR_FILES.PNG","HELP_YOUR_FILES.TXT","HELP_YOURFILES.HTML","HELPDECRYPT.TXT","HELPDECYPRT_YOUR_FILES.HTML","HOW DECRIPT FILES.hta","How decrypt files.hta","How Decrypt My Files.lnk","How To Decode Files.hta","how to decrypt aes files.lnk","HOW TO DECRYPT FILES.HTML","HOW TO DECRYPT FILES.txt","How to decrypt LeChiffre files.html","How to decrypt your data.txt","How to decrypt your files.jpg","How to decrypt your files.txt","how to decrypt*.*","How to decrypt.txt","HOW TO DECRYPT[1T0tO].txt","how to get back you files.txt","How to get data back.txt","how to get data.txt","HOW TO RECOVER ENCRYPTED FILES-infovip@airmail.cc.TXT","HOW TO RECOVER ENCRYPTED FILES.TXT","How to restore files.hta","How To Restore Files.txt","HOW-TO-DECRYPT-FILES.HTM","HOW-TO-DECRYPT-FILES.HTML","HOW-TO-RESTORE-FILES.txt","HOW_CAN_I_DECRYPT_MY_FILES.txt","how_decrypt.gif","HOW_DECRYPT.HTML","HOW_DECRYPT.TXT","HOW_DECRYPT.URL","HOW_DECRYPT_FILES#.html","How_Decrypt_Files.hta","How_Decrypt_My_Files","HOW_OPEN_FILES.hta","how_recover*.*","HOW_RETURN_FILES.TXT","how_to_back_files.html","how_to_decrypt*.*","HOW_TO_DECRYPT.HTML","HOW_TO_DECRYPT.txt","HOW_TO_DECRYPT_FILES.html","HOW_TO_DECRYPT_FILES.TXT","HOW_TO_DECRYPT_MY_FILES.txt","How_to_decrypt_your_files.jpg","HOW_TO_FIX_!.TXT","how_to_recover*.*","How_To_Recover_Files.txt","how_to_recver_files.txt","How_to_restore_files.hta","HOW_TO_RESTORE_FILES.html","HOW_TO_RESTORE_FILES.txt","HOW_TO_RESTORE_YOUR_DATA.html","how_to_unlock*.*","HOW_TO_UNLOCK_FILES_README_*.txt","HowDecrypt.gif","HowDecrypt.txt","howrecover+*.txt","howto_recover_file.txt","HOWTO_RECOVER_FILES_*.*","HOWTO_RECOVER_FILES_*.TXT","howto_restore*.*","Howto_RESTORE_FILES.html","Howto_Restore_FILES.TXT","HowToBackFiles.txt","howtodecrypt*.*","howtodecryptaesfiles.txt","HowToDecryptIMPORTANT!.txt","HowtoRESTORE_FILES.txt","HUR_DEKRYPTERA_FILER.html","HUR_DEKRYPTERA_FILER.txt","HVORDAN_DU_GENDANNER_FILER.html","HVORDAN_DU_GENDANNER_FILER.txt","HWID Lock.exe","IAMREADYTOPAY.TXT","IF YOU WANT TO GET ALL YOUR FILES BACK, PLEASE READ THIS.TXT","IF_WANT_FILES_BACK_PLS_READ.html","IF_YOU_WANT_TO_GET_ALL_YOUR_FILES_BACK_PLEASE_READ_THIS.TXT","IHAVEYOURSECRET.KEY","IMPORTANT READ ME.txt","Important!.txt","IMPORTANT.README","Important_Read_Me.txt","Info.hta","infpub.dat","install_tor*.*","INSTALL_TOR.URL","INSTRUCCIONES.txt","INSTRUCCIONES_DESCIFRADO.html","INSTRUCCIONES_DESCIFRADO.TXT","Instruction for file recovery.txt","INSTRUCTION RESTORE FILE.TXT","INSTRUCTION_FOR_HELPING_FILE_RECOVERY.txt","Instructionaga.txt","Instructions with your files.txt","INSTRUCTIONS_DE_DECRYPTAGE.html","ISTRUZIONI_DECRITTAZIONE.html","JSWORM-DECRYPT.hta","keybtc@inbox_com","KryptoLocker_README.txt","last_chance.txt","lblBitcoinInfoMain.txt","lblFinallyText.txt","lblMain.txt","LEER_INMEDIATAMENTE.txt","LEIA_ME.txt","les#.TXT","Lock.","Locked.*","locked.bmp","loptr-*.htm","lukitus.html","matrix-readme.rtf","maxcrypt.bmp","MENSAGEM.txt","MERRY_I_LOVE_YOU_BRUCE.hta","message.txt","mood-ravishing-hd-wallpaper-142943312215.jpg","NEWS_INGiBiToR.txt","NFS-e*1025-7152.exe","NOTE;!!!-ODZYSKAJ-PLIKI-!!!.TXT","OKSOWATHAPPENDTOYOURFILES.TXT","OKU.TXT","OkuBeni.txt","ONTSLEUTELINGS_INSTRUCTIES.html","oor.","oor.*","OSIRIS-*.*","OSIRIS-*.htm","ownertrust.txt","PadCrypt.exe","padcryptUninstaller.exe","Paxynok.html","paycrypt.bmp","payload.dll","PAYMENT-INSTRUCTIONS.TXT","Payment_Advice.mht","Payment_Instructions.jpg","Perfect.sys","petwrap.exe","PLEASE-READIT-IF_YOU-WANT.html","popcorn_time.exe","pronk.txt","qwer.html","qwer2.html","qwerty-pub.key","random","Rans0m_N0te_Read_ME.txt","Ransom.rtf","ransomed.html","READ IF YOU WANT YOUR FILES BACK.html","Read Me (How Decrypt) !!!!.txt","READ ME ABOUT DECRYPTION.txt","READ ME FOR DECRYPT.txt","Read me for help thanks.txt","READ TO UNLOCK FILES.salsa.*.html","READ-READ-READ.html","Read.txt","READ@My.txt","READ__IT.txt","READ_DECRYPT_FILES.txt","READ_IT.txt","READ_IT_FOR_GET_YOUR_FILE.txt","READ_ME.cube","READ_ME.html","READ_ME.mars","READ_ME_!.txt","READ_ME_ASAP.txt","READ_ME_FOR_DECRYPT_*.txt","READ_ME_HELP.png","READ_ME_HELP.txt","READ_ME_TO_DECRYPT_YOU_INFORMA.jjj","Read_this_file.txt","READ_THIS_FILE_1.TXT","READ_THIS_TO_DECRYPT.html","READ_TO_DECRYPT.html","ReadDecryptFilesHere.txt","README HOW TO DECRYPT YOUR FILES.HTML","README!!!.txt","Readme-Matrix.rtf","README-NOW.txt","ReadME-Prodecryptor@gmail.com.txt","readme.hta","readme_decrypt*.*","ReadME_Decrypt_Help_*.html","README_DECRYPT_HYDRA_ID_*.txt","README_DECRYPT_HYRDA_ID_*.txt","README_DECRYPT_UMBRE_ID_*.jpg","README_DECRYPT_UMBRE_ID_*.txt","ReadMe_Decryptor.txt","readme_for_decrypt*.*","README_FOR_DECRYPT.txt","README_HOW_TO_UNLOCK.HTML","README_HOW_TO_UNLOCK.TXT","ReadMe_Important.txt","readme_liesmich_encryptor_raas.txt","README_LOCKED.txt","README_RECOVER_FILES_*.html","README_RECOVER_FILES_*.png","README_RECOVER_FILES_*.txt","Readme_Restore_Files.txt","README_TO_RECURE_YOUR_FILES.txt","READTHISNOW!!!.TXT","Receipt.exe","RECOVER-FILES.html","recover.bmp","recover.txt","recoverfile*.txt","recovery+*.*","Recovery+*.html","Recovery+*.txt","RECOVERY_FILE*.txt","recovery_file.txt","RECOVERY_FILES.txt","recovery_key.txt","recoveryfile*.txt","Recupere seus arquivos aqui.txt","redchip2.exe","Restore Files.TxT","RESTORE-.-FILES.txt","RESTORE-12345-FILES.TXT","RESTORE-SIGRUN.*","RESTORE_CORUPTED_FILES.HTML","RESTORE_FILES.HTML","restore_files.txt","RESTORE_FILES_*.*","RESTORE_FILES_*.txt","RESTORE_HCEEM_DATA.txt","Restore_ICPICP_Files.txt","RESTORE_INFO-*.txt","Restore_maysomware_files.html","Restore_your_files.txt","restorefiles.txt","rtext.txt","Runsome.exe","ryukreadme.html","Sarah_G@ausi.com___","Sarah_G@ausi.com___*","ScreenLocker_x86.dll","SECRET.KEY","SECRETIDHERE.KEY","SECURITY-ISSUE-INFO.txt","SGUARD-README.TXT","SHTODELATVAM.txt","Sifre_Coz_Talimat.html","SIFRE_COZME_TALIMATI.html","SintaLocker.exe","SintaRun.py","Spreader_x86.dll","SsExecutor_x86.exe","strongcrypt.bmp","StrutterGear.exe","Survey Locker.exe","svchosd.exe","t.wry","tabDll*.dll","taskdl.exe","taskhsvc.exe","tasksche.exe","taskse.exe","Tempimage.jpg","ThxForYurTyme.txt","tor.exe","TOTALLYLEGIT.EXE","tox.html","TrumpHead.exe","TRY-READ-ME-TO-DEC.html","TUTORIEL.bmp","UnblockFiles.vbs","unCrypte@outlook.com*","UNLOCK_FILES_INSTRUCTIONS.html","UNLOCK_FILES_INSTRUCTIONS.txt","UselessDisk.exe","Vape Launcher.exe","vault.hta","vault.key","vault.txt","vesad","VictemKey_*_*","VIP72.exe","Wannacry.exe","WannaCry.TXT","WannaCrypt 4.0.exe","warning.txt","wcry.exe","wcry.zip","WE-MUST-DEC-FILES.html","What happen to my files.txt","WhatHappenedWithFiles.rtf","WhatHappenedWithMyFiles.rtf","WHERE-YOUR-FILES.html","wie_zum_Wiederherstellen_von_Dateien.txt","winclwp.jpg","WindowsApplication1.exe","Wo_sind_meine_Dateien.htm*","wormDll*.dll","x5gj5_gmG8.log","xort.txt","YOU_MUST_READ_ME.rtf","YOUGOTHACKED.TXT","Your files are locked !!!!.txt","Your files are locked !!!.txt","Your files are locked !!.txt","Your files are locked !.txt","Your files are now encrypted.txt","Your files encrypted by our friends !!! txt","Your files encrypted by our friends !!!.txt","YOUR_FILES.HTML","YOUR_FILES.url","YOUR_FILES_ARE_DEAD.hta","YOUR_FILES_ARE_ENCRYPTED.HTML","YOUR_FILES_ARE_ENCRYPTED.TXT","YOUR_FILES_ARE_LOCKED.txt","your_key.rsa","YourID.txt","zcrypt.exe","Zenis-*.*","Zenis-Instructions.html","ZINO_NOTE.TXT","zXz.html","zycrypt.*","zzzzzzzzzzzzzzzzzyyy","инструкция по оплате.txt","Инструкция по расшифровке.TXT")
	# ONLY if you use the Experiant download you may want to use the following commented variable because Experient does not supply exclusions (that's a good thing)
	# to use this you just uncomment and populate it with your chosen file group exclusions
	# the local json file method includes this information but it is an extension to, and not included with the Experiant JSON format
	# this variable cannot be an empty string (""), either leave it undefined or populate it with meaningful information
	# legacy note - these are file group Exclude Files, they are not the same as SkipList.txt entries
	# $FnameExtExclude = @("this_is_just_a_dummy_placeholder_string","replace_it_with_meaningful_information_if_necessary","excluded_file_specs")

	$LocalJsonFilePathAndPattern = $PSScriptRoot+"\"+"combined-"+$JSONfnamesubstring+"-????????_??????.json"
	$HoneyPotFileGroupName = "HoneyPotAllFilesWildcard"
	$HoneyPotFilters = @("*.*")
	# the following exclusions are so common that I think it's OK to exclude them by default, mostly dropped by curious internal folks, let's not lock them out for this
	$HoneyPotExclusions = $("thumbs.db","desktop.ini")

	$RansomwareTemplateName = "RansomwareFnamesAndExtsCheck"
	$HoneyPotTemplateName = "RansomwareHoneyPotCheck" # hard coded to be passive, we want to capture some of the bad guys' files to help identify decryption methods

	# Creates file path to store block smb script that is called by the FSRM template
	# set this variable ($TriggeredScriptDestination) to your desired script location but NO SPACES in the path names
	$TriggeredScriptDestination = "C:\PROGRA~1\FSRM-triggered-scripts" # important: no spaces in this string, that's why we're using the 8.3 formatted C:\PROGRA~1\
	$TriggeredScriptFullPath = $TriggeredScriptDestination+"\DenyPermissionsEventParsing.PS1" # important!!!: no spaces in this string
	# build a string that's used by the file screen template command parameter, this is how we get the user name into the deny access script
	# comment out this variable if you don't want the triggered script to run
	$TriggeredCommandParm = "-Command `"& {"+$TriggeredScriptFullPath+" -username '[Source Io Owner]'}`""
	# END - ADDITIONAL VARIABLES THAT NEED TO BE SET AND VALIDATED #

	# make sure a "source" has been setup in the event log, this should be first executable line
	# we'll just force it blindly every time, detecting sources is too convoluted and this won't hurt anything
	New-EventLog -LogName $EventLog -Source $EventLoggingSource -ErrorAction SilentlyContinue
	$message = "Script version: " + $CurrentVersion + "`nInformation:`nNormal script startup`n"
    # build a text list of all variables from the param block, format them for easy reading
    [string]$localformattedparmstring = (Get-Command -Name $PSCommandPath).Parameters | Format-Table -AutoSize @{ Label = "Key"; Expression={$_.Key}; }, @{ Label = "Value"; Expression={(Get-Variable -Name $_.Key -EA SilentlyContinue).Value}; } | Out-String
    $message = $message +"`nParam block variables and values:"+ $localformattedparmstring
	Write-Host $message
	Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 1 -EntryType Information -Message $message
	
	# The "Requires -Version 4" statement at the top is to enforce that the script is being run as administrator
	# The rest of this script is compatible with version 3. You may override this version check if you're stuck with PS 3 but you must insure that you're running as admin.
	# For Windows 2012x you should add WMF 5.1 to your server which upgrades the PowerShell to version 5.1. See additional info in the notes. WMF 5.1 is standard in W2016 and W2019.
	Write-Host "`nTesting PowerShell version 4 or above"
	If ($PSVersionTable.PSVersion.Major -lt 4)
		{
		$message = "Script version: " + $CurrentVersion + "`nError:`nWrong version of PowerShell detected`nThis script requires PowerShell version 4 or above.`n`nAborting script.`nIt is possible to override this requirement but you must insure you're running this script as administrator.`nA better alternative is to install Windows Management Framwork (WMF) 5.1`nSee the special PowerShell 3 instructions in this script.`n"
		$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
		Write-Host -ForegroundColor Red -BackgroundColor Black $message
		Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 2001 -EntryType Error -Message $message
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
		$message = "Script version: " + $CurrentVersion + "`nError:`nWrong version of Windows detected`nThis script will only run on Windows 2012 and higher, and will only run on Server editions of Windows.`n`nAborting script.`n"
		$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
		Write-Host -ForegroundColor Red -BackgroundColor Black $message
		Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 2002 -EntryType Error -Message $message
		Exit
		}

	Write-Host "`nTesting variables configured"
	If (-not $YesAllTheVariablesAreSetHowIWant)
		{
		$message = "Script version: " + $CurrentVersion + "`nError:`nScript unconfigured`nThis script implements very critical security measures.`nIt is imperative that you understand and edit the configuration variables in this script.`nYou will find them in the param() block and in the begin{} section.`nWhen all the settings are configured how you want them use the`n -YesAllTheVariablesAreSetHowIWant `$True`nparameter and rerun this script.`n`nAborting script.`n"
		$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
		Write-Host -ForegroundColor Red -BackgroundColor Black $message
		Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 2003 -EntryType Error -Message $message
		Exit
		}	
	#add the FSRM role if it doesnt exist
	Write-Host "`nVerifying FSRM is installed"
	If ((Get-WindowsFeature fs-resource-manager).installed -like "False")
		{
		$message = "Script version: " + $CurrentVersion + "`nWarning:`nInstalling FSRM`nYou will only see this warning message when this script is installing the FSRM role.`nRead the following messages from the Windows installer carefully. You may need to reboot manually.`nRerun this script when the FSRM installation has finished.`nNote - for Windows 2012 and 2012r2 only:`nThe FSRM service can be a little unstable immediately after the FSRM role is installed.`nIf you see errors when you rerun this script then stop and restart the FSRM service and then rerun this script again.`n"
		$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
		Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
		Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 1001 -EntryType Warning -Message $message
		Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
		Exit
		}
	} # end Begin clause
  
Process
	{
	# we always need some sort of SMTP setup (this if clause will execute for both reinstallation of FSRM and partial installations that needed to be rebooted to complete, kludge but necessary)
	Write-Host "`nVerifying SMTP server and admin email address settings in FSRM"
	If (((Get-FsrmSetting).SmtpServer -ne $SMTPServer) -or ((Get-FsrmSetting).AdminEmailAddress -ne $AdminEmailTo))
		{
		$message = "Script version: " + $CurrentVersion + "`nWarning:`nThe current global FSRM SMTP server and destination email address settings do not match this script's settings.`nThe current settings in this script are SMTP: `"$SMTPServer`" and Admin email: `"$AdminEmailTo`" .`nIf this is the first time you've run this script after installing FSRM then`nthe settings from the variables will be applied.`nIf this is not the first time you've run this script after installing FSRM then`nthe current settings in FSRM will be replaced with the values shown just above.`nYou will need to close and then reopen the FSRM manager to view the new settings because`nthere is no refresh option for global settings.`nFinally, use the FSRM manager to send a test message just to be sure everything works the way you expect.`n"
		$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
		Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
		Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 1002 -EntryType Warning -Message $message
		Set-FsrmSetting -SmtpServer $SMTPServer -AdminEmailAddress $AdminEmailTo  -FromEmailAddress $EmailFrom -CommandNotificationLimit 0 -EmailNotificationLimit 1 -EventNotificationLimit 0 -ReportFileScreenAuditEnable
		Write-Host "`nVerifying SMTP server and admin email reset"
		if ($? -ne $True)
			{
			# you should never get here but it is so important that we have to check the return value
			$message = "Script version: " + $CurrentVersion + "`nError:`nA critical error has occurred setting the global settings in FSRM.`nSettings include SMTP server, admin email address, from email address, and notification timers.`nThe FSRM file screens will not function correctly until this error is corrected.`n`nAborting script.`n"
			$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
			Write-Host -ForegroundColor Red -BackgroundColor Black $message
			Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 2004 -EntryType Error -Message $message
			Exit
			}
		}

	# this is so important that we'll check every time the script is run, sorry to be heavy handed but you have no choice, this is a critical security issue
	# the command notification limit must be set to 0, anything but 0 will prevent the lockout script from running more than once within the timer interval
	# the event notification limit should be set to 0, we want every trigger to be logged in the Windows event logs
	Write-Host "`nVerifying command and event notification limits set to 0 (zero)"
	If (((Get-FsrmSetting).CommandNotificationLimit -ne 0) -or ((Get-FsrmSetting).EventNotificationLimit -ne 0))
		{
		$message = "Script version: " + $CurrentVersion + "`nWarning:`nThe FSRM global settings for both Command Notification and Event Notification must be set to zero (0)`nThe triggered scripts and email notifications will not work reliably if the notification values are set to ANYTHING else.`nYou're seeing this message because the values were not zero. They will be reset to the correct values now.`n"
		$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
		Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
		Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 1003 -EntryType Warning -Message $message
		Set-FsrmSetting -CommandNotificationLimit 0 -EventNotificationLimit 0
		if ($? -ne $True)
			{
			$message = "Script version: " + $CurrentVersion + "`nError:`nA critical error has occurred setting the global notification timers in FSRM.`nThe FSRM file screens will not function correctly until this error is corrected.`n`nAborting script.`n"
			$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
			Write-Host -ForegroundColor Red -BackgroundColor Black $message
			Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 2005 -EntryType Error -Message $message
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
			$message = "Script version: " + $CurrentVersion + "`nWarning:`nDownloading filters list from $LegacyDownloadFiltersJsonURL failed.`nUsing built-in defaults for now.`nMust be remediated for maximum protection.`n"
			$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
			Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
			Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 1004 -EntryType Warning -Message $message
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
		if (Test-Path -Path $TempIncludeListTxtPath)
		    {
		    # read the Include List file and appende to $FnameExtFilters
			$FnameExtFilters = $FnameExtFilters + (Get-Content -LiteralPath $TempIncludeListTxtPath | ForEach-Object {$_.Trim()})
			# dedupe
			$FnameExtFilters = $FnameExtFilters | Select-Object -Unique
			$message = "`nInformation:`nIncludeList.txt read successfully from $TempIncludeListTxtPath`n"
			Write-Host $message
			Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 12 -EntryType Information -Message $message
			}
		else
		    {
			$message = "Script version: " + $CurrentVersion + "`nWarning:`nDid not find an IncludeList.txt file.`n"
			$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
			Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
			Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 1007 -EntryType Warning -Message $message
			}
		
		# remove SkipList.txt entries (equivalent of extended-data.allowed in the extended format JSON)
		$TempSkipListTxtPath = $PSScriptRoot + "`\SkipList.txt"
		if (Test-Path -Path $TempSkipListTxtPath)
		    {
			# read in the filters that should be allowed, the Skip List
			$TempSkipList = Get-Content -LiteralPath $TempSkipListTxtPath | ForEach-Object {$_.Trim()}
			# now remove them from $FnameExtFilters
		    $FnameExtFilters = $FnameExtFilters | Where-Object {$TempSkipList -notcontains $_}
			$message = "`nInformation:`nSkipList.txt read successfully from $TempSkipListTxtPath`n"
			Write-Host $message
			Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 13 -EntryType Information -Message $message
		    }
		else
		    {
			$message = "Script version: " + $CurrentVersion + "`nWarning:`nDid not find an IncludeList.txt file.`n"
			$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
			Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
			Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 1008 -EntryType Warning -Message $message
		    }
		}
	Else
		{
		Write-Host "`nSearching for local JSON file matching:`n$LocalJsonFilePathAndPattern`n"
		$LocalJsonFile = Get-ChildItem -Path $LocalJsonFilePathAndPattern | Sort-Object -Property PSChildName | Select-Object -Last 1
		If ($LocalJsonFile -eq $null)
			{
			$message = "Script version: " + $CurrentVersion + "`nWarning:`nNo input JSON file matching $LocalJsonFilePathAndPattern found.`nUsing built-in defaults for now.`nMust be remediated for maximum protection.`n"
			$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
			Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
			Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 1005 -EntryType Warning -Message $message
			}
		else
			{
			Write-Host "`nReading filters and exceptions from local JSON file:`n$LocalJsonFile`n"
			$FromJSONdata = Get-Content -Path $LocalJsonFile -Raw | ConvertFrom-Json
			# testing $? does work here, but testing for null value is more comprehensive and tests json conversion too
			If ($FromJSONdata -eq $null)
				{
				$message = "Script version: " + $CurrentVersion + "`nWarning:`nThe Get-Content import from $LocalJsonFile filters file failed.`nUsing built-in defaults for now.`nMust be remediated for maximum protection.`n"
				$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
				Write-Host -ForegroundColor Yellow -BackgroundColor Black $message
				Write-EventLog -LogName Application -Source $EventLoggingSource -Category 0 -EventID 1006 -EntryType Warning -Message $message
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

	If ($RefreshHoneyPots) # refresh requested, delete all existing, (no error if none found)
		{
		# delete all existing honey pot file screens
		$message = "`nInformation:`nPurging $HoneyPotTemplateName file screens`n"
		Write-Host $message
		Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 6 -EntryType Information -Message $message
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
	$action3 = New-FsrmAction -Type Command -SecurityLevel LocalSystem -Command "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -CommandParameters $TriggeredCommandParm -WorkingDirectory $TriggeredScriptDestination -ShouldLogError -KillTimeOut 1
	$message = "`nInformation:`nCreating/Updating file screen templates`n"
	Write-Host $message
	Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 8 -EntryType Information -Message $message
	# process the ransomware template
	If (Get-FsrmFileScreenTemplate | Where-Object -Property Name -eq $RansomwareTemplateName) # It must have existed already so we'll just update it
		{
		# note: we are pushing this update to ALL derived file screens, not just the directly matching file screens
		Write-Host "`nUpdating $RansomwareTemplateName template"
		Set-FsrmFileScreenTemplate -Name $RansomwareTemplateName -UpdateDerived -Active:$RansomwareTemplateIsActive -IncludeGroup $RansomeWareFileGroupName -Description "This template traps files with extensions on the likely ransomware list" -Notification $action1,$action2,$action3
		}
	Else
		{
		Write-Host "`nCreating $RansomwareTemplateName template"
		New-FsrmFileScreenTemplate -Name $RansomwareTemplateName -Active:$RansomwareTemplateIsActive -IncludeGroup $RansomeWareFileGroupName -Description "This template traps files with extensions on the likely ransomware list" -Notification $action1,$action2,$action3
		}
	#process the honey pot templates
	# note:
	# the -Active:$false is not well documented but this is the only way to make the template passive, passive will allow the user to keep creating files until the access is revoked
	# this template should always be passive to allow that bad guys to create files and not detect an access denied condition
	If (Get-FsrmFileScreenTemplate | Where-Object -Property Name -eq $HoneyPotTemplateName) # It must have existed already so we'll just update it
		{
		# note: we are pushing this update to ALL derived file screens, not just the directly matching file screens
		Write-Host "`nUpdating $HoneyPotTemplateName template"
		Set-FsrmFileScreenTemplate -Name $HoneyPotTemplateName -UpdateDerived -Active:$false -IncludeGroup $HoneyPotFileGroupName -Description "This template detects any file creation in our honey pot directories." -Notification $action1,$action2,$action3
		}
	Else
		{
		Write-Host "`nCreating $HoneyPotTemplateName template"
		New-FsrmFileScreenTemplate -Name $HoneyPotTemplateName -Active:$false -IncludeGroup $HoneyPotFileGroupName -Description "This template detects any file creation in our honey pot directories." -Notification $action1,$action2,$action3
		}

	$message = "`nInformation:`nCreating/Updating triggered script `"$TriggeredScriptFullPath`"`n"
	Write-Host $message
	Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 9 -EntryType Information -Message $message
	# Creates Script Block to block SMB Permissions. Exports script block to a PS1 for the File Screen Template.
	# String-Here is positional, all white space is included, do not indent the following (anytying after @" through "@)
	$DenyPermissionsTriggeredScript = @"
param( [string]`$username = "" )
Get-SmbShare | Where-Object currentusers -gt 0 | Block-SmbShareAccess -AccountName `$username -force

# This is the antidote to unlock the user's share access, convenience copy just for you
# Get-SmbShare | Unblock-SmbShareAccess -AccountName PUT_USERNAME_HERE -force -ErrorAction SilentlyContinue

# brute force restart of FSRM services to override notification settings if they are not set to 0, shouldn't be necessary but it's here if you need it
# Restart-Service "File Server Resource Manager" -force
"@
	If (-not (Test-Path -Type Container -Path $TriggeredScriptDestination))
		{
		New-Item -Path $TriggeredScriptDestination -Force -Type directory
		}
	$DenyPermissionsTriggeredScript | Out-File -FilePath $TriggeredScriptFullPath
	#unblocks the script to allow for execution 
	Unblock-file $TriggeredScriptFullPath

	# Note:
	# You MAY use both the monitoring drives and the monitoring share methods together, since roots of drives can't be shared there will never be direct conflicts
	# File screens at lower levels (farther from the root) of the file system always override the file screens applied closer to the root
	# there is no Set-FsrmFileScreen PowerShell command because they are modified by their templates
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
			ForEach-Object {If (-not (Get-FsrmFileScreen -Path $_.DeviceID -ErrorAction SilentlyContinue)) {New-FsrmFileScreen -Path $_.DeviceID -Template $RansomwareTemplateName} }
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
		Get-SmbShare | Select-Object -Property * | 
		Where-Object {($_.Special -ne "True") -and ($_.ShareType -eq "FileSystemDirectory")  -and ($_.Path -notlike "C:\Windows\*")} | 
		ForEach-Object -Process {Get-ChildItem -Path $_.Path -Force -ErrorAction SilentlyContinue -Directory -Filter $HoneyPotDirectoryNamePattern} | 
		Select-Object -Property FullName | 
		ForEach-Object {If (-not (Get-FsrmFileScreen -Path $_.FullName -ErrorAction SilentlyContinue)) {New-FsrmFileScreen -Path $_.FullName -Template $HoneyPotTemplateName}}
		}
	$message = "Script version: " + $CurrentVersion + "`nInformation:`nNormal script shutdown`n"
	$message = $message +"`nParam block variables and values:"+ $localformattedparmstring
	Write-Host $message
	Write-EventLog -LogName $EventLog -Source $EventLoggingSource -Category 0 -EventID 999 -EntryType Information -Message $message
	} # end Process clause
}
InstallUpdate-FSRMRansomwareScreening
