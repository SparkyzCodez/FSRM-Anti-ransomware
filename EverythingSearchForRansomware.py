#! /usr/bin/env python3
import string, json, datetime, pathlib, copy, argparse, stat, logging, subprocess, ctypes, struct, csv
from time import sleep

'''This application will read in a JSON file containing Anti-ransomware filters and search all local NTFS and ReFS drives for matching files.
Notes:
  all local NTFS and ReFS drives will be searched
  a dictionary that maps directly written to JSON is our primary internal data bucket, but writing to JSON is not mandatory
  no data files are written by default
  all matches will go to stdout
  input JSON file uses the same wildcard matching as AntiransomwareFiltersMerge.py but may be overridden
  Everything.exe
    !! important - the SDK does not support named instances so we have to work with what we found,
      it's up to the user to make sure their existing Everything setup can see all local drives
      future to do: we'll spin up our own instance of Everything so there's no interference from whatever was already running
    by default we start Everything, use it, then kill it - use the --donotkill flag to leave it running when we're done
  Everything64.dll
    only supporting 64 bit version, no provision for 32 bit since this is a server oriented app, if you specify a 32 bit version then we'll try but it's totally unsupported
'''
# initialize psuedo constants
INTERNAL_NAME = 'EverythingSearchForRansomware.py'
VERSION = '1.1.0'
DEBUG_SIMULATATE_COMMAND_LINE = False

#defines for Everything SDK
EVERYTHING_REQUEST_FILE_NAME = 0x00000001
EVERYTHING_REQUEST_PATH = 0x00000002
EVERYTHING_REQUEST_FULL_PATH_AND_FILE_NAME = 0x00000004
EVERYTHING_REQUEST_EXTENSION = 0x00000008
EVERYTHING_REQUEST_SIZE = 0x00000010
EVERYTHING_REQUEST_DATE_CREATED = 0x00000020
EVERYTHING_REQUEST_DATE_MODIFIED = 0x00000040
EVERYTHING_REQUEST_DATE_ACCESSED = 0x00000080
EVERYTHING_REQUEST_ATTRIBUTES = 0x00000100
EVERYTHING_REQUEST_FILE_LIST_FILE_NAME = 0x00000200
EVERYTHING_REQUEST_RUN_COUNT = 0x00000400
EVERYTHING_REQUEST_DATE_RUN = 0x00000800
EVERYTHING_REQUEST_DATE_RECENTLY_CHANGED = 0x00001000
EVERYTHING_REQUEST_HIGHLIGHTED_FILE_NAME = 0x00002000
EVERYTHING_REQUEST_HIGHLIGHTED_PATH = 0x00004000
EVERYTHING_REQUEST_HIGHLIGHTED_FULL_PATH_AND_FILE_NAME = 0x00008000

# for testing only - a way to fake command line args
if DEBUG_SIMULATATE_COMMAND_LINE:
  print ('\nXXXXX: Warning - debugging command line override is enabled in source code, replaces command line arguments pre-parsing :XXXXX')
  import sys
  sys.argv = [sys.argv[0], '-v', '--donotkill', '--reporttext', '--jsonresults', '--csvresults', '-n','bosco']
  # sys.argv = [sys.argv[0], '-V']
  # sys.argv = [sys.argv[0], '-n', 'bosco']
  # sys.argv = [sys.argv[0], '-d','-o','-w','C:\\Temp\\scratch']


def IntializeApp()->dict:
  '''Performs all program initialization EXCEPT the output JSON dictionary.
  Notes:
    !! hard coding note !! - too many hard coded items to list individually, most hard coding is here (where it belongs)
    evaluates command line options with argparse, generates td strings, verifies working directory and optional input JSON
    override file and secondary input JSON file paths, sets verbosity for logging, loads runtime control baton  
  Inputs:
    none passed in
    argv
  Outputs:
    returns - a runtime control baton (dictionary) loaded with all runtime control items including operational flags, file name wildcards,
    working directory, URL, output file name, etc.
  '''
  # init our runtime control baton dict
  runcontrol = {}

  # just a simple line return visual cue that the app has started running, only cosmetic, a little seperation from the prompt never hurts
  print()

  # setup logging
  consoleformatter = logging.Formatter(fmt='%(message)s - %(levelname)s')
  consolehandler = logging.StreamHandler()
  consolehandler.setFormatter(consoleformatter)
  runcontrol['log'] = logging.getLogger(INTERNAL_NAME)
  runcontrol['log'].addHandler(consolehandler)
  
  # command line parsing
  argsparser = argparse.ArgumentParser(allow_abbrev=False, description='Fighting ransomware everyday: This program reads in a combined JSON file with only "filters" or an extended JSON file with both "filters" and "exceptions" lists of file specs, and searches local hard drives for matching files using the same methodology as Microsoft File Server Resource Manager file screening. By default this program lists all files that match "filters" except those that also match "exceptions". Optionally you may find all files without processing the exceptions. This is also a great tool to test filter optimizations before putting them in production.')

  argsparser.add_argument('-n', '--fnamesubstring', type=str, default='extended', help = 'substring for both for wildcard file name matching of input primary JSON file as well as naming the output data files, default substring is "extended", format example: "combined-extended-20191031_123456.json"')
  argsparser.add_argument('-p', '--primaryjsonoverride', type=str,help='primary JSON input file, overrides default primary file found through wildcard matching with fnamesubstring, use full file path name, does not affect output data file names')
  argsparser.add_argument('-w', '--workingdirectory', type=str, default='', help='working directory for source and destination of files, if not specified then uses the OS current working directory')

  argsparser.add_argument('-c', '--csvresults', default=False, action='store_true', help = 'write CSV results file, processed data with "exceptions" excluded unless --noexceptions was specified')
  argsparser.add_argument('-r', '--reporttext', default=False, action='store_true', help = 'write a text report (identical to data displayed to screen), processed data with "exceptions" excluded unless --noexceptions was specified')
  # argsparser.add_argument('-e', '--emailresults', type=str, default='', help='sends email with report text results in the body, only works with non-authenticated email, you may have more than one destination email address - just add them to the end, config example: "smtp.example.org,25,evsnotification@example.org,destmail1@example.org,destmail2@example.org"')
  # argsparser.add_argument('-x', '--noexceptions', default=False, action='store_true', help = 'this will find all files matching input JSON "filters" without processing "exceptions", by default files that match "exceptions" will not be included in CSV and text results (JSON output always lists both filter and exception matches)')
  argsparser.add_argument('-j', '--jsonresults', default=False, action='store_true', help = 'JSON output includes "filters-allhits" and "exceptions-allhits", and an additional attribute "filters-FSRMmatched" that always has matching "exceptions" removed similar to FSRM, the --noexceptions option is always ignored')

  argsparser.add_argument('-d', '--donotkill', default=False, action='store_true', help = 'leave Everything.exe running after we\'re finished searching')
  argsparser.add_argument('--dbstarttimeout', default=120, type=int, help = 'in seconds, timeout wait for the Everything engine to start, default is 2 minutes which is easily long enough for 5 million or fewer files')
  argsparser.add_argument('--everythingdll', type=str, default='Everything64.dll', help = 'by default we\'ll look for the Everything DLL in same directory as this app, override here with full path including the file name, path will not be searched')
  argsparser.add_argument('--everythingexe', type=str, default='Everything.exe', help = 'by default we\'ll look for the Everything.exe executable in same directory as this app, override here with full path including the file name, path will not be searched')

  # note: we're going to rotate the output files by default, we don't want to fill their hard drive with files
  # I see it as the user implicitly approving this behavior
  argsparser.add_argument('--compactjson', default=False, action='store_true', help = 'the default JSON ouput format is pretty print (easy to read), this option will change it to compact')
  argsparser.add_argument('-t', '--rotatefilescount', default=5, type=int, help = 'keep ROTATEFILESCOUNT most recent files then rotate, program default: 5, 0 to disable, if you do not want file rotation then you must specify a rotate files count of 0 (integer expected)')
  argsparser.add_argument('-V', '--version', default=False, action='store_true', help = 'display version and exit')

  verbositycontrol = argsparser.add_mutually_exclusive_group()
  verbositycontrol.add_argument('-v', '--verbose', default=False, action='store_true', help = 'verbose output - displays all debug messages including Everything debug data (debug window may not appear if Everything was already running), may not be used with --quiet')
  verbositycontrol.add_argument('-q', '--quiet', default=False, action='store_true', help = 'quiet output - only warnings and errors displayed, may not be used with --verbose')

  cmdlineargs = argsparser.parse_args()

  ## special case -V/--version, mimics -h raising of SystemExit ##
  if cmdlineargs.version:
    runcontrol['log'].setLevel(logging.DEBUG)
    runcontrol['log'].info(INTERNAL_NAME+'\nVersion: '+VERSION+'\nRun with -h / --help parameter for usage details.')
    raise SystemExit
    
  # set logging level, be explicit, default is to show warning and above only
  if cmdlineargs.verbose:
    runcontrol['log'].setLevel(logging.DEBUG)
  elif cmdlineargs.quiet:
    runcontrol['log'].setLevel(logging.WARNING)
  else:
    runcontrol['log'].setLevel(logging.INFO)

  runcontrol['log'].debug('initializing application runtime control')

  # tell the user about any significant behavior they should expect, especially dry run since they may miss an updated filter list
  # should be warnings
  #just info
  if cmdlineargs.primaryjsonoverride:
    runcontrol['log'].info('--primaryjsonoverride specified on command line, primary input JSON file is : ' + cmdlineargs.primaryjsonoverride)
  if cmdlineargs.donotkill:
    runcontrol['log'].info('--donotkill specified on command line, Everything.exe will be left running')

  # a little verbose but we'll put all our fname parts here, easy to customize, easy to convert to command line parms
  fnamesep = '-'
  fnameprefix = 'combined'  # this matches the prefix for Experiant supplied JSON files
  fnamesubstring = cmdlineargs.fnamesubstring
  fnametimestampwildcard = '????????_??????'  # this matches our file name datestamp format
  fnameEverythingsubstring = 'everythingsearchresults'
  fnamejsonext = '.json'
  fnamecsvext = '.csv'
  fnametextext = '.txt'

  # time and date strings
  nowtimezulu = datetime.datetime.utcnow()
  # time date string for json embedded data
  runcontrol['nowstringzulu'] = nowtimezulu.strftime('%Y-%m-%dT%H:%M:%S.%fZ') # note: actually relying on the microseconds would be silly, it's just for completeness
  # local time zone time date string for adding to file names
  runcontrol['nowsubstrlocltz'] = nowtimezulu.replace(tzinfo=datetime.timezone.utc).astimezone(tz=None).strftime('%Y%m%d_%H%M%S')

  # we'll validate our working directory here, a number of initializations just below rely on it
  #   working with pure paths and then instantiating a real path elsewhere in the program is too much brain damage
  try:
    runcontrol['workdirpath'] = pathlib.Path(cmdlineargs.workingdirectory).resolve()
    runcontrol['workdirpath'].exists()
  except:
    runcontrol['log'].error('cannot find working directory: ' + cmdlineargs.workingdirectory)
    raise

  # wildcard for finding all matching input candidate JSON files
  runcontrol['jsonfnamewildcard'] = (fnameprefix+fnamesep+fnamesubstring+fnamesep+fnametimestampwildcard+fnamejsonext)
  
  # full path for new output JSON file
  pathtemp = (fnameprefix+fnamesep+fnamesubstring+fnamesep+runcontrol['nowsubstrlocltz']+fnamesep+fnameEverythingsubstring+fnamejsonext)
  runcontrol['opjsonfullpath'] = pathlib.Path(runcontrol['workdirpath'], pathtemp).resolve()
  runcontrol['opjsonwildcard'] = (fnameprefix+fnamesep+fnamesubstring+fnamesep+fnametimestampwildcard+fnamesep+fnameEverythingsubstring+fnamejsonext)
  
  # full path for new output CSV file
  pathtemp = (fnameprefix+fnamesep+fnamesubstring+fnamesep+runcontrol['nowsubstrlocltz']+fnamesep+fnameEverythingsubstring+fnamecsvext)
  runcontrol['opcsvfullpath'] = pathlib.Path(runcontrol['workdirpath'], pathtemp).resolve()  
  runcontrol['opcsvwildcard'] = (fnameprefix+fnamesep+fnamesubstring+fnamesep+fnametimestampwildcard+fnamesep+fnameEverythingsubstring+fnamecsvext)

  # full path for new output text file
  pathtemp = (fnameprefix+fnamesep+fnamesubstring+fnamesep+runcontrol['nowsubstrlocltz']+fnamesep+fnameEverythingsubstring+fnametextext)
  runcontrol['optextfullpath'] = pathlib.Path(runcontrol['workdirpath'], pathtemp).resolve()
  runcontrol['optextwildcard'] = (fnameprefix+fnamesep+fnamesubstring+fnamesep+fnametimestampwildcard+fnamesep+fnameEverythingsubstring+fnametextext)

  # file rotation stack
  # this is for tuples in the form (path, wildcard) for globbing in rotation function
  runcontrol['rotatequeue'] = []

  # Everything control
  # needs to be defined for final cleanup to know what to do
  runcontrol['evs'] = None
  # Everything 1stwait is just for the intial "is there anybody out there" test in seconds, non-fatal if no one is home, cold start time out comes from command line
  runcontrol['evs1stwait'] = 10 # second wait is controlled from command line args
  runcontrol['evsexerunning'] = False
  runcontrol['evslaunchparms'] = [cmdlineargs.everythingexe, '--startup', '--nodb', '--admin']
  if cmdlineargs.verbose:
    runcontrol['evslaunchparms'].extend(['--debug','--verbose'])
  runcontrol['evsexepopen'] = None #subprocess Popen class

  # full copy of the command line args object
  runcontrol['cmdlineargs'] = copy.deepcopy(cmdlineargs)
  runcontrol['log'].debug('runtime control baton initialized')
  return runcontrol


# initializes the output JSON data structure, there are quite a few hard coded items in here
def IntializeData(runcontrol:dict)->dict:
  '''This initializes the output JSON dictionary only.
  Notes:
    !! hard coding note !! - hard coding items in here are limited to formatting and pre-loading of the output JSON dictionary
  Inputs:
    runtime control baton
  Outputs:
    returns - initialized but otherwise empty ouput JSON dictonary
  '''
  runcontrol['log'].debug('initializing application data')

  skeleton = dict.fromkeys(['api', 'lastUpdated', 'filters-FSRMmatched', 'filters-allhits', 'exceptions-allhits'])
  skeleton['api'] = dict.fromkeys(['format','extended-info'])
  skeleton['api']['extended-info'] = dict.fromkeys(['PrimaryInputJSONfile', 'thisfilename', 'SourceWasOptimized'])
 
  skeleton['api']['format'] = 'json'
  skeleton['api']['extended-info']['PrimaryInputJSONfile'] = ''
  skeleton['api']['extended-info']['thisfilename'] = runcontrol['opjsonfullpath'].name
  skeleton['api']['extended-info']['SourceWasOptimized'] = False
  skeleton['lastUpdated'] = runcontrol['nowstringzulu']
  skeleton['filters-FSRMmatched'] = {}
  skeleton['filters-allhits'] = {}
  skeleton['exceptions-allhits'] = {}
  runcontrol['log'].debug('output JSON data structure initialized')
  return skeleton

def EverythingInit(runcontrol:dict)->None:
  '''This launches and initializes Everything database engine.
  Notes:
    these steps are based on the SDK Python example
    future to do: launch our own instance so we minimize any side effects from the config of an already running instance, not yet supported in the SDK
  Inputs:
    runtime control baton
  Outputs:
    returns - nothing
    !! 2 exit points using return, one if Everything is already running, another if we launch it
  '''
  # load the SDK DLL
  try:
    runcontrol['log'].info('loading Everything/VoidTools SDK DLL (see included Everything VoidTools License)')
    runcontrol['evs'] = ctypes.WinDLL(runcontrol['cmdlineargs'].everythingdll)
  except OSError:
    runcontrol['log'].error('OS error loading Everything DLL')
    raise
  except:
    runcontrol['log'].error('unhandled exception loading Everything DLL')
  else:
    runcontrol['log'].debug('successfully loaded Everything/VoidTools SDK DLL')
    # the following line is here if we want to add date information to the results, but not now
    # runcontrol['evs'].Everything_GetResultDateModified.argtypes = [ctypes.c_int,ctypes.POINTER(ctypes.c_ulonglong)]
    runcontrol['evs'].Everything_GetResultSize.argtypes = [ctypes.c_int,ctypes.POINTER(ctypes.c_ulonglong)]

  # let's see if Everything is already running
  #   later we'll change this and spin up our own instance, for now we'll just use it if it's running
  runcontrol['log'].info('1st try contacting previously running Everything database engine, normally takes up to ' + str(runcontrol['evs1stwait']) + ' seconds')
  for n in range(runcontrol['evs1stwait']):
    runcontrol['evsexerunning'] = runcontrol['evs'].Everything_IsDBLoaded()
    if runcontrol['evsexerunning']:
      # it would be rude to close a previously running instance, block that
      runcontrol['cmdlineargs'].donotkill = True
      # non-fatal but we have warn the user that it's on them to have Everything setup correctly
      runcontrol['log'].warning('Everything is already running, you must insure that you\'re current config allows visibility to all local drives and files')
      return
    else:
      sleep(1)

  # Everything is not yet running - supersedes first wait once we can launch our own instance
  #   generate a random string for our instance name, see if it's already running (it's not, but check anyway)

  # launch Everything and wait for it to poll all the local drives, about 40 seconds for 2.5 million files
  # launch Everything
  try:
    runcontrol['log'].info('loading Everything database engine (see included Everything VoidTools License), be patient, may take up to ' + str(runcontrol['cmdlineargs'].dbstarttimeout) +' seconds')
    subprocess.Popen(runcontrol['evslaunchparms'])
  except FileNotFoundError:
    runcontrol['log'].error('Cannot find Everything.exe database engine')
    raise
  except OSError:
    runcontrol['log'].error('OS error launching Everything database engine')
    raise
  except:
    runcontrol['log'].error('unhandled exception launching Everything database engine')
    raise

  loadedflag = False
  for n in range(runcontrol['cmdlineargs'].dbstarttimeout):
    runcontrol['evsexerunning'] = runcontrol['evs'].Everything_IsDBLoaded()
    if runcontrol['evsexerunning']:
      runcontrol['log'].debug('successfully contacted Everything database engine')
      loadedflag = True
      return
    else:
      sleep(1)

  if loadedflag == False:
    runcontrol['log'].error('unable to launch Everything database engine within --dbstarttimeout timeout window')
    raise Exception

def FindLoadPrimaryJSON(runcontrol:dict)->dict:
  '''This globs for, and then loads the primary input JSON data.
  Notes:
    uses wildcard glob info from the runtime control baton
    assumes sorted list of matched files, -1 index is newest
  Inputs:
    runtime control baton
  Outputs:
    returns - dictionary loaded with primary JSON data
  '''
  # primary json file override handling
  runcontrol['log'].debug('primary input JSON loading')
  if runcontrol['cmdlineargs'].primaryjsonoverride:
    try:
      fnamepathtest = pathlib.Path(runcontrol['cmdlineargs'].primaryjsonoverride).resolve()
      fnamepathtest.exists()
    except:
      runcontrol['log'].error('primary input JSON file specified on command line not found')
      raise
    else:
      infilelist = [fnamepathtest]  # needs to be a list
  else:
    infilelist = list(runcontrol['workdirpath'].glob(runcontrol['jsonfnamewildcard'])) # list of pathlib.Path objects
    infilelist.sort()

  try:
    with open(infilelist[-1], 'r', encoding='utf-8') as infilejson:
      pjsondata = json.load(infilejson)
  except json.decoder.JSONDecodeError:
    runcontrol['log'].error('unable to parse JSON data from ' + infilejson.name)
    raise
  except(LookupError,OSError):
    # LookupError is when glob doesn't find anything and the -1 index is invalid, OSError will catch any related open or close exceptions
    runcontrol['log'].error('no primary input JSON candidate files found - working directory: '+runcontrol['workdirpath'].name+'  wildcard mask: '+runcontrol['jsonfnamewildcard'])
    raise
  except Exception:
    runcontrol['log'].error('unhandled exception during primary input JSON file - working directory: '+runcontrol['workdirpath'].name+'  wildcard mask: '+runcontrol['jsonfnamewildcard'])
    raise
  else:
    runcontrol['log'].info('primary input JSON read from file: ' + infilelist[-1].name)

  try:
    pjsondata['filters']
  except:
    runcontrol['log'].error('no filters found in primary input JSON, required attribute, it must exist even if it is empty')
  else:
    return pjsondata


def EvsSearch(opjson:dict, ipjson:dict, runcontrol:dict)->dict:
  '''This searches through the Everything engine for all matching files.
  Notes:
    does a little housekeeping that may not really belong here, it's simple and this is a convenient spot
    !! hard coding - magic number !! the file name buffer based on ctypes is hard coded to 4096 bytes, find a constant that's OS specific to use
    !! hard coding - magic number !! just used modulo 100 for filters search progress messages, and modulo 10 for the exceptions
  Inputs:
    initialized output JSON
    input JSON - as const
    runtime control baton
  Outputs:
    output JSON data
  '''
  runcontrol['log'].debug('beginning Everything searches')
  # filename buffer !!! magic number !!! -> convert to some max file len constant for the OS if there is one, 4096 should do for almost anything, could be 64k - 1
  filename = ctypes.create_unicode_buffer(4096)
  # a little housekeeping
  try:
    opjson['api']['extended-info']['PrimaryInputJSONfile'] = ipjson['api']['extended-info']['thisfilename']
    opjson['api']['extended-info']['SourceWasOptimized'] = ipjson['api']['extended-info']['thisfileoptimized']
  except KeyError:
    # this is a nothing burger, if this is a simple combined JSON then it won't have this attribute, just mention it and move on
    ipjson['exceptions'] = []
    opjson['api']['extended-info']['SourceWasOptimized'] = False
    runcontrol['log'].debug('it appears we\'re using a non-extended input JSON file, no "exceptions" processing will take place')

  # search for filters matches
  fspecsearchcount = 0
  for fspec in ipjson['filters']:
    # setup the query
    hitlist = []
    runcontrol['evs'].Everything_SetSearchW('utf8:case:file:noregex:ww:wfn:"'+fspec+'"')
    runcontrol['evs'].Everything_SetRequestFlags(EVERYTHING_REQUEST_FILE_NAME | EVERYTHING_REQUEST_PATH)

    #execute the query
    runcontrol['evs'].Everything_QueryW(1)

    # process results
    for i in range(runcontrol['evs'].Everything_GetNumResults()):
      runcontrol['evs'].Everything_GetResultFullPathNameW(i,filename,len(filename))
      hitlist.append(ctypes.wstring_at(filename))

    fspecsearchcount += 1
    if (not runcontrol['cmdlineargs'].quiet) and (not fspecsearchcount % 100):
      print(fspecsearchcount, '"filters" filespecs searched so far')

    if len(hitlist) > 0:
      opjson['filters-allhits'][fspec] = hitlist
      opjson['filters-allhits'][fspec].sort()
      runcontrol['log'].info('input JSON "filters" matched ' + str(len(hitlist)) + ' files on filespec ' + fspec)

  runcontrol['log'].info(str(fspecsearchcount) + ' "filters" filespecs searched')

  # search for exceptions matches
  fspecsearchcount = 0
  for fspec in ipjson['exceptions']:
    # setup the query
    hitlist = []
    runcontrol['evs'].Everything_SetSearchW('utf8:case:file:noregex:ww:wfn:"'+fspec+'"')
    runcontrol['evs'].Everything_SetRequestFlags(EVERYTHING_REQUEST_FILE_NAME | EVERYTHING_REQUEST_PATH)

    #execute the query
    runcontrol['evs'].Everything_QueryW(1)

    # process results
    for i in range(runcontrol['evs'].Everything_GetNumResults()):
      runcontrol['evs'].Everything_GetResultFullPathNameW(i,filename,len(filename))
      hitlist.append(ctypes.wstring_at(filename))

    fspecsearchcount += 1
    if (not runcontrol['cmdlineargs'].quiet) and (not fspecsearchcount % 10):
      print(fspecsearchcount, '"exceptions" filespecs searched so far')

    if len(hitlist) > 0:
      opjson['exceptions-allhits'][fspec] = hitlist
      opjson['exceptions-allhits'][fspec].sort()
      runcontrol['log'].info('input JSON "exceptions" matched ' + str(len(hitlist)) + ' files on filespec ' + fspec)

  runcontrol['log'].info(str(fspecsearchcount) + ' "exceptions" filespecs searched')


def FiltersScreen(jsondata:dict, runcontrol:dict)->None:
  '''This removes file names that match the exceptions from the filters.
  Notes:
  Inputs:
    JSON data
    runtime control baton
  Outputs:
    JSON data with FSRM matched file names
  '''
  runcontrol['log'].info('processing filters and exceptions, genrating FSRM style matched files list')
  # build a flat list that contains all exceptions regardless of matching fspec
  exceptionsflat = []
  for fspec in jsondata['exceptions-allhits']:
    exceptionsflat.extend(jsondata['exceptions-allhits'][fspec])

  # search for filters-allhits for file names that do not appear in exceptions-allhits
  # loop through each dictionary
  for fspec in jsondata['filters-allhits']:
    hitlist = []
    # loop through fspec's list of matches
    for fname in jsondata['filters-allhits'][fspec]:
      if fname not in exceptionsflat: hitlist.append(fname)
    
    if len(hitlist) > 0:
      jsondata['filters-FSRMmatched'][fspec] = hitlist
      jsondata['filters-FSRMmatched'][fspec].sort()



def WriteOpJSON(opjson:dict, runcontrol:dict)->None:
  '''This writes the updated JSON data to file.
  Notes:
    !! hard coding note !! - the output encoding is hard coded to utf-8 text, JSON dumping escapes Unicode characters
      don't let the 'ensure-ascii' in JSON dump fool you, it insures proper escaping but we're Unicode conforming from end to end
    do not sort the JSON, we're trying to keep all the attributes in the same order that we set them up in the init
  Inputs:
    JSON dictionary
    runtime control baton
  Outputs:
    none
    returns - none
  '''
  runcontrol['log'].debug('writing output JSON file')
  try:
    if runcontrol['cmdlineargs'].compactjson:
      jsondatstring = json.dumps(opjson, ensure_ascii=True)
    else:
      jsondatstring = json.dumps(opjson, ensure_ascii=True, sort_keys=False, indent=2)
  except: # from json.dump, likely ValueError, could be TypeError, catch 'em all, any exception that's not OSError will be from JSON serializing
    runcontrol['log'].error('error serializing output JSON data or other unhandled exception, output file will not be written')

  try:
    with open(runcontrol['opjsonfullpath'], 'w', encoding='utf-8') as outfilejson:
      outfilejson.write(jsondatstring)
  except OSError:
    runcontrol['log'].error('failed to write ouput JSON file ' + str(runcontrol['opjsonfullpath']))
    raise
  except:
    runcontrol['log'].error('unhandled exception writing ouput JSON file ' + str(runcontrol['opjsonfullpath']))
    raise
  else:
    runcontrol['rotatequeue'].append((runcontrol['workdirpath'], runcontrol['opjsonwildcard']))
    runcontrol['log'].info('JSON ouput data written to file: ' + runcontrol['opjsonfullpath'].name)


def WriteFlatCSV(opjson:dict, runcontrol:dict)->None:
  '''This writes the flat CSV file containing only the 'filters-FSRMmatched' data.
  Notes:
    writes only the filters-FSRMmatched from the output JSON data
    files are encoded with non-escaped utf-8 Unicode, no BOM 
    one text file has one filter per line
    the other text file has filters in a format specifically for PowerShell scripts, wrapped in double quotes and comma seperated
    to do - could a join of some sort to work for the script format? so much to learn   
  Inputs:
    JSON dictionary
    runtime control baton
  Outputs:
    none
    returns - none
  '''
  flatlist = []
  header = ('Match Type', 'Matched Filters', 'Matched File Names')
  for fspec in opjson['filters-FSRMmatched']:
    for fname in opjson['filters-FSRMmatched'][fspec]:
      flatlist.append(('filters-FSRMmatched', fspec, fname))
  for fspec in opjson['exceptions-allhits']:
    for fname in opjson['exceptions-allhits'][fspec]:
      flatlist.append(('exceptions-allhits', fspec, fname))
  try:
    with open(runcontrol['opcsvfullpath'], 'w', encoding='utf-8', newline='') as outfilecsv:
      outcsv = csv.writer(outfilecsv, dialect='excel')
      outcsv.writerow(header)
      for row in flatlist:
        outcsv.writerow(row)
  except OSError:
    runcontrol['log'].error('error writing flat CSV file ' + runcontrol['opcsvfullpath'].name)
  except:
    runcontrol['log'].error('unhandle exception writing flat CSV file ' + runcontrol['opcsvfullpath'].name)
  else:
    runcontrol['rotatequeue'].append((runcontrol['workdirpath'], runcontrol['opcsvwildcard']))
    runcontrol['log'].info('flat CSV written to file: ' + runcontrol['opcsvfullpath'].name)


def ReportTextGen(opjson:dict, runcontrol:dict)->None:
  '''This generates the text used for the report file and screen display.
  Notes:
    files are encoded with non-escaped utf-8 Unicode, no BOM
 Inputs:
    JSON dictionary
    runtime control baton
  Outputs:
    none
    returns - none
  '''
  hitlist = []
  hitlist.append('Generated by: ' + INTERNAL_NAME + '   (' + VERSION + ')' + '\n')
  hitlist.append('This file: ' + runcontrol['optextfullpath'].name + '\n')
  hitlist.append('Input source file: ' + opjson['api']['extended-info']['PrimaryInputJSONfile'] + '\n')
  hitlist.append('Input source was optimized: ' + str(opjson['api']['extended-info']['SourceWasOptimized']) + '\n')

  if len(opjson['filters-FSRMmatched']) > 0:
    hitlist.append('\n-- filters-FSRMmatched' + ' - Matching filters found --\n')
    for fspec in opjson['filters-FSRMmatched']:
      hitlist.append(fspec + '\n')
      for fname in opjson['filters-FSRMmatched'][fspec]:
        hitlist.append(fname + '\n')
      hitlist.append('\n')
  else:
    hitlist.append('\n-- filters-FSRMmatched' + ' - No matching filters found --\n\n')

  if len(opjson['exceptions-allhits']) > 0:
    hitlist.append('\n-- exceptions-allhits' + ' - Matching filters found --\n')
    for fspec in opjson['exceptions-allhits']:
      hitlist.append(fspec + '\n')
      for fname in opjson['exceptions-allhits'][fspec]:
        hitlist.append(fname + '\n')
      hitlist.append('\n')
  else:
    hitlist.append('\n-- exceptions-allhits' + ' - No matching filters found --\n\n')

  runcontrol['report'] = hitlist


def WriteReportText(runcontrol:dict)->None:
  '''This writes the text report file file.
  Notes:
  Inputs:
    runtime control baton
  Outputs:
    none
    returns - none
  '''
  try:
    with open(runcontrol['optextfullpath'], 'w', encoding='utf-8') as outfiletext:
      for row in runcontrol['report']:
        outfiletext.write(row)
        # outfiletext.write('\n')
  except OSError:
    runcontrol['log'].error('error writing the report text file ' + runcontrol['optextfullpath'].name)
  except:
    runcontrol['log'].error('unhandle exception writing the report text file ' + runcontrol['optextfullpath'].name)
  else:
    runcontrol['rotatequeue'].append((runcontrol['workdirpath'], runcontrol['optextwildcard']))
    runcontrol['log'].info('report text file written to file ' + runcontrol['optextfullpath'].name)


def WriteTextToDisplay(runcontrol:dict)->None:
  '''This displays only the 'filters-FSRMmatched' data to the screen.
  Notes:
  Inputs:
    ouput JSON
    runtime control baton
  Outputs:
    none
    returns - none
  '''
  print()
  for row in runcontrol['report']:
    print(row, end='')

def RotateFiles(runcontrol:dict)->None:
  '''This rotates and deletes all types of files that we've written in this pass.
  Notes:
    !! hard coding note !! - we are blindly changing the mode of any file to be deleted to RW
    deletes oldest file based on its file name td stamp and not the OS file date
    if ancillary files weren't written this pass then they won't be rotated
  Inputs:
    runtime control baton
  Outputs:
    none
    returns - none
  '''
  # find all the files matching the wildcard (based on tuples stored in rotatequeue)
  for rotateitem in runcontrol['rotatequeue']:
    infilelist = list(rotateitem[0].glob(rotateitem[1]))
    infilelist.sort()
    for n in range(0, len(infilelist)-runcontrol['cmdlineargs'].rotatefilescount):
      try:
        # we're hard coding rw stat on the file, the user has implicitly authorized deletion by not setting --rotatefilescount to zero
        (infilelist[n]).chmod(stat.S_IWRITE)
        pathlib.Path.unlink(infilelist[n])
      except:
        runcontrol['log'].warning('unable to rotate/delete ' + infilelist[n].name)
      else:
        runcontrol['log'].info('rotated/deleted ' + infilelist[n].name)


# MAIN #
# this try block catches normal argrparse SystemExit automatically raised by -h/--help and parsing errors, and manually raised by -V/--version
# SystemExit is a child of the BaseException class and not Exception, it will never get caught by "exception:"
try:
  runtimecontrol = IntializeApp()
  opjsondata = IntializeData(runtimecontrol)
  EverythingInit(runtimecontrol)
  EvsSearch(opjsondata, FindLoadPrimaryJSON(runtimecontrol), runtimecontrol)
  FiltersScreen(opjsondata, runtimecontrol)
  
  if runtimecontrol['cmdlineargs'].jsonresults: # write JSON
    WriteOpJSON(opjsondata, runtimecontrol)
  if runtimecontrol['cmdlineargs'].csvresults: # write CSV
    WriteFlatCSV(opjsondata, runtimecontrol)
  if runtimecontrol['cmdlineargs'].reporttext or runtimecontrol['cmdlineargs'].verbose:
    # write text report
    ReportTextGen(opjsondata, runtimecontrol)
    if runtimecontrol['cmdlineargs'].reporttext:
      WriteReportText(runtimecontrol)
    if runtimecontrol['cmdlineargs'].verbose:
      WriteTextToDisplay(runtimecontrol)
  if runtimecontrol['cmdlineargs'].rotatefilescount > 0:
      RotateFiles(runtimecontrol)

except SystemExit:
  # only explicitly raised in InitializeApp(), never matches an 'except:' clause, we could just let it fall through the bottom of the program but I think we should be specific
  raise
except:
  # this is just to create a little visual separation at the command line and then re-raise any exceptions
  # future to do: maybe put additional exception handling here
  print()
  raise
finally:
  ### to do maybe - move this into a EverythingCleanup(), not really enough action to worry about here, 2 tasks and some logging
  try:
    runtimecontrol
  except NameError:
    # program never initialized, nothing to do but just get out
    pass
  else:
    if runtimecontrol['evs']:
      if not runtimecontrol['cmdlineargs'].donotkill:
        # just a blind kill for now, if it failed to exit what would we do at this point anyway? we could push another error message
        runtimecontrol['log'].debug('shutting down Everything')
        runtimecontrol['evs'].Everything_Exit()
      runtimecontrol['log'].debug('unloading Everything SDK DLL')
      runtimecontrol['evs'].Everything_CleanUp()
