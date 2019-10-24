#! /usr/bin/env python3
"""
Processes JSON formatted input(s) continaining lists of filter strings for use with Windows FSRM.
Run with -h parameter for usage details.

Notes:
This script assumes that the filters will be applied to a case INSENSITIVE file system using Microsoft Windows' FSRM.
The regex optimization section of this script is case INSENSITIVE (in two places). Everything else in this script is case sensitive.
Filters processing is lossless. Once a filespec is added to "filters" will never be removed. You have these options for recourse.
    1. EITHER add the exact matching string to extended-data.excludefromfilters OR match with regex and replace with an empty string (best, easiest)
    2. start over and use the --reloadfromsecondaryfilters option, the secondary may still contain the filter you want to remove so you may need option 1 anyway
    3. build an empty skeleton JSON file and load it with a fresh set of filters AND manage your secondary input filters manually. (hardest)
regex whole string matches may use empty strings "" as their replacement
pretty print formatted JSON will sometimes fail on PowerShell v4 and below Get-Content when piplined to ConvertFrom-Json
  in PowerShell do this: Get-Content -Raw | Convert-FromJson
    the "-Raw" flag fixes the problem, forces all json to be stored in a single string, otherwise each line goes into an array of strings
    alternative: use the -c/--compactjson option in this program
all input JSON data is assumed to be encoded in UTF-8 Unicode format because many ransomware file names have Unicode characters
all string operations are Unicode conforming
  all internal string handling is 100% Unicode, all wide all the time
  the input files MAY use ascii escaping of Unicode characters
  JSON output file WILL use ascii escaping of Unicode characters
  text output files are non-escaped Unicode
all output files (JSON and text files) are encoded in UTF-8 Unicode but with no BOM marker
  (a BOM should never be necessary for Utf-8)
"""
# version 3.1.1 - minor bugfix runtimecontrol to runcontrol in defs, primary JSON attribute name changes, clarify description + notes at top

import string, json, re, urllib, urllib.request, datetime, pathlib, copy, argparse, stat, logging

# initialize psuedo constants
INTERNAL_NAME = 'AntiransomwareFiltersMerge.py'
VERSION = '3.1.1'
DEBUG_SIMULATATE_COMMAND_LINE = False

# for testing only - a way to fake command line args
if DEBUG_SIMULATATE_COMMAND_LINE:
  print ('\nXXXXX: Warning - debugging command line override is enabled in source code, replaces command line arguments pre-parsing :XXXXX')
  import sys
  # sys.argv = [sys.argv[0], '-h']
  sys.argv = [sys.argv[0], '-a', '-n', 'pinkard', '-g']
  # sys.argv = [sys.argv[0],   '-v', '-f', '-a', '-t','1', '-o', '-s', 'combined-20190925.json']  # tested local secondary
  # sys.argv = [sys.argv[0], '-k','-n','blizard'] # generated a skeleton, skipped blizard, correct behavior
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
  argsparser = argparse.ArgumentParser(allow_abbrev=False, description='Fighting ransomware everyday: This program is an accessory to FSRM-Anti-ransomware.ps1 PowerShell script, also available from us, that helps you fight ransomware on your Windows file servers using File Server Resource Manager (FSRM) file screening functionality. This program allows you to manage and extend a basic combined.json file (updated frequently and available from fsrm.experiant.ca) so that you can easily manage your allowed file names and special exceptions while keeping your file groups updated with the latest ransomware file specifications. We are not affiliated in any way with Experiant but we very deeply appreciate all their efforts to keep us safe from ransomware by keeping track of the latest ransomware threats in the wild. Getting Started: Use this program to generate a skeleton, rename the skeleton file by changing the substring in the middle, load that skeleton with additional information such as allowed file specs and exception file names, then use this program to merge your customized information with updated filters from third parties like Experiant. Use the fnamesubstring option to match your file name or just use the default of "extended" as your substring. This program will never delete any filters you\'ve added unless you refresh all the filters from the secondary source.',epilog='This is part of an important security implementation that leverages Microsoft\'s FSRM. Make sure you understand the options in both FSRM and this program. Take your time. Be deliberate.')

  argsparser.add_argument('-n', '--fnamesubstring', type=str, default='extended', help = 'substring for both for wildcard file name matching of input primary JSON file as well as naming the output JSON file, default substring is "extended", format example: "combined-extended-20191031_123456.json"')
  argsparser.add_argument('-p', '--primaryjsonoverride', type=str,help='primary JSON input file, overrides default primary file found through wildcard matching with fnamesubstring, use full file path name, does not affect output JSON file name')

  filtersourcegroup = argsparser.add_mutually_exclusive_group()
  filtersourcegroup.add_argument('-g', '--groomingonly', default=False, action='store_true', help='groom only performs grooming on primary JSON, useful to enable or disable optimization without adding new filters, secondary JSON will be ignored, may not be used with --reloadfromsecondaryfilters')
  filtersourcegroup.add_argument('-r', '--reloadfromsecondaryfilters', default=False, action='store_true',help='refresh "filters" from secondary, only secondary JSON filters will be processed, primary JSON filters will be lost, all other data from primary JSON will be carried forward, be careful with this option because you will lose any of your manually added filters, may not be used with --groomingonly')

  secondaryjsongroup = argsparser.add_mutually_exclusive_group()
  secondaryjsongroup.add_argument('-u', '--url', type=str, default='https://fsrm.experiant.ca/api/v1/combined', help='download URL for secondary JSON filters data, program default is Experiant\'s up to date combined.json from: https://fsrm.experiant.ca/api/v1/combined, may not be used with --localsecondaryjson or -groomingonly')
  secondaryjsongroup.add_argument('-s', '--localsecondaryjson', type=str, default=None, help='local file for secondary JSON input, alternative to downloading, use explict path and name, may not be used with --url or -groomingonly')

  argsparser.add_argument('-o', '--optimizefilters', default=False, action='store_true', help = 'agressive optimization of filters using regex that you\'ve added to the primary input json, use with caution, test results before moving into production')
  argsparser.add_argument('-c', '--compactjson', default=False, action='store_true', help = 'disables pretty print JSON, only necessary if your PowerShell JSON parsing is failing')
  argsparser.add_argument('-a', '--ancillarytextfiles', default=False, action='store_true', help = 'write ancillary text files')
  argsparser.add_argument('-k', '--skeletononly', default=False, action='store_true', help = 'creates a minimally initialized JSON file, FNAMESUBSTRING will always be set to "skeleton", any FNAMESUBSTRING specified on the command line will be ignorned')
  argsparser.add_argument('-w', '--workingdirectory', type=str, default='', help='working directory for source and destination of files, if not specified then uses the OS current working directory')

  outputwritecontrol = argsparser.add_mutually_exclusive_group()
  outputwritecontrol.add_argument('-d', '--dryrun', default=False, action='store_true', help = 'dry run, output files are not written, may not be used with --force')
  outputwritecontrol.add_argument('-f', '--force', default=False, action='store_true', help = 'force output files to be written even if no changes were detected, may not be used with --dryrun')

  # note: we're going to rotate files by default, this program could be called for years without being checked, we don't want to fill their hard drive with files
  # I see it as the user implicitly approving this behavior
  argsparser.add_argument('-t', '--rotatefilescount', default=5, type=int, help = 'keep ROTATEFILESCOUNT most recent files then rotate, program default: 5, 0 to disable, (integer expected)')
  argsparser.add_argument('-V', '--version', default=False, action='store_true', help = 'display version and exit')

  verbositycontrol = argsparser.add_mutually_exclusive_group()
  verbositycontrol.add_argument('-v', '--verbose', default=False, action='store_true', help = 'verbose output - all debug messages displayed, may not be used with --quiet')
  verbositycontrol.add_argument('-q', '--quiet', default=False, action='store_true', help = 'quiet output - only warnings and errors displayed, may not be used with --verbose')

  cmdlineargs = argsparser.parse_args()

  ## special case -V/--version, mimics -h raising of SystemExit ##
  if cmdlineargs.version:
    runcontrol['log'].setLevel(logging.DEBUG)
    runcontrol['log'].info(INTERNAL_NAME+'\nVersion:'+VERSION+'\nRun with -h / --help parameter for usage details.')
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
  if cmdlineargs.dryrun:
    runcontrol['log'].warning('--dryrun specified on command line, no files will be written')
  if cmdlineargs.groomingonly:
    runcontrol['log'].warning('--groomingonly specified on command line, reprocessing primary filters only')
  if cmdlineargs.reloadfromsecondaryfilters:
    runcontrol['log'].warning('--reloadfromsecondaryfilters specified on command line, reloading from secondary filter source only, primary filters will be discarded')
  if cmdlineargs.skeletononly:
    runcontrol['log'].warning('--skeletononly specified on command line, creating an empty primary JSON file only, example name format: "combined-skeleton-20100101-123456"')
  if cmdlineargs.optimizefilters:
    runcontrol['log'].warning('--optimizefilters specified on command line, applying regex optimizations to merged filters, test your results thoroughly')
  #just info
  if cmdlineargs.primaryjsonoverride:
    runcontrol['log'].info('--primaryjsonoverride specified on command line, primary input JSON file is : ' + cmdlineargs.primaryjsonoverride)
  if cmdlineargs.localsecondaryjson:
    runcontrol['log'].info('--localsecondaryjson specified on command line, secondary input JSON file is : ' + cmdlineargs.localsecondaryjson)
  if cmdlineargs.force:
    runcontrol['log'].info('--force specified on command line, files will be written even if no changes are detected')

  # a little verbose but we'll put all our fname parts here, easy to customize, easy to convert to command line parms
  fnamesep = '-'
  fnameprefix = 'combined'  # this matches the prefix for Experiant supplied JSON files
  fnamesubstring = cmdlineargs.fnamesubstring
  if cmdlineargs.skeletononly:
    fnamesubstring = 'skeleton'
  fnametimestampwildcard = '????????_??????'  # this matches our file name datestamp format
  fnamejsonext = '.json'
  fnametextprefix = 'filters'
  fnameonepersubstring = 'one_per_line_utf8'
  fnamescrptfrmtsubstring = 'script_formatted_utf8'
  fnametextext = '.txt'

  # now see if our directories and input files exist, no sense doing anything else until we know
  try:
    runcontrol['workdirpath'] = pathlib.Path(cmdlineargs.workingdirectory).resolve()
    runcontrol['workdirpath'].exists()
  except:
    runcontrol['log'].error('cannot find working directory: ' + cmdlineargs.workingdirectory)
    raise
  else:
    # ok, our starting point path exists, now we look for special cases too
    # primary json file
    if cmdlineargs.primaryjsonoverride:
      try:
        fnamepathtest = pathlib.Path(cmdlineargs.primaryjsonoverride).resolve()
        fnamepathtest.exists()
      except:
        runcontrol['log'].error('primary input JSON file specified on command line not found')
        raise
      else:
        runcontrol['primaryjsonoverridepath'] = fnamepathtest

    # secondary json file, don't look for it if skeletononly option enabled
    if cmdlineargs.localsecondaryjson and not cmdlineargs.skeletononly:
      try:
        fnamepathtest = pathlib.Path(cmdlineargs.localsecondaryjson).resolve()
        fnamepathtest.exists()
      except:
        runcontrol['log'].error('secondary JSON file specified on command line not found')
        raise
      else:
        runcontrol['secondaryjsonpath'] = fnamepathtest

  # time and date strings
  nowtimezulu = datetime.datetime.utcnow()
  # time date string for json embedded data
  runcontrol['nowstringzulu'] = nowtimezulu.strftime('%Y-%m-%dT%H:%M:%S.%fZ') # note: actually relying on the microseconds would be silly, it's just for completeness
  # local time zone time date string for adding to file names
  runcontrol['nowsubstrlocltz'] = nowtimezulu.replace(tzinfo=datetime.timezone.utc).astimezone(tz=None).strftime('%Y%m%d_%H%M%S')

  # wildcard for finding all matching input candidate JSON files
  runcontrol['jsonfnamewildcard'] = (fnameprefix+fnamesep+fnamesubstring+fnamesep+fnametimestampwildcard+fnamejsonext)
  
  # full path for new output JSON file
  jsonopfname = (fnameprefix+fnamesep+fnamesubstring+fnamesep+runcontrol['nowsubstrlocltz']+fnamejsonext)
  runcontrol['opjsonpath'] = pathlib.Path(runcontrol['workdirpath'], jsonopfname).resolve()
  
  # full paths and matching wildcards for filters only ancillary text files
  pathtemp = (fnametextprefix+fnamesep+fnamesubstring+fnamesep+fnameonepersubstring+fnamesep+runcontrol['nowsubstrlocltz']+fnametextext)
  runcontrol['opfiltersoneperlnpath'] = pathlib.Path(runcontrol['workdirpath'], pathtemp).resolve()  
  runcontrol['opfiltersoneperlnwildcard'] = (fnametextprefix+fnamesep+fnamesubstring+fnamesep+fnameonepersubstring+fnamesep+fnametimestampwildcard+fnametextext)
  pathtemp = (fnametextprefix+fnamesep+fnamesubstring+fnamesep+fnamescrptfrmtsubstring+fnamesep+runcontrol['nowsubstrlocltz']+fnametextext)
  runcontrol['opfiltersPSlistpath'] = pathlib.Path(runcontrol['workdirpath'], pathtemp).resolve()
  runcontrol['opfiltersPSlistwildcard'] = (fnametextprefix+fnamesep+fnamesubstring+fnamesep+fnamescrptfrmtsubstring+fnamesep+fnametimestampwildcard+fnametextext)
  # keys for looping for file rotation, if you add an additional text file type then add the wildcard key to this list
  runcontrol['opfilterstextrotatekeys'] = ['opfiltersoneperlnwildcard', 'opfiltersPSlistwildcard']

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
  EXTENDED_JSON_VERSION = 3.1   # format version of JSON ouput file, change this any time the skeleton format is changed

  skeleton = dict.fromkeys(['api','lastUpdated','exceptions','filters','extended-data'])
  skeleton['api'] = dict.fromkeys(['format','file_group_count','extended-info'])
  skeleton['api']['extended-info'] = dict.fromkeys(['extended-version','SecondaryLastUpdated','thisfilename','optimizationwarning','thisfileoptimized'])
  skeleton['extended-data'] = dict.fromkeys(['excludefromfilters','deltasinceprev','regexsubstringsubs','regexsummarizations','losslesstracking'])
  skeleton['extended-data']['losslesstracking'] = dict.fromkeys(['addedfilters','removedfilters'])

  skeleton['api']['format'] = 'json'
  skeleton['api']['file_group_count'] = 0
  skeleton['api']['extended-info']['extended-version'] = EXTENDED_JSON_VERSION
  skeleton['api']['extended-info']['SecondaryLastUpdated'] = ''
  skeleton['api']['extended-info']['thisfilename'] = runcontrol['opjsonpath'].name
  skeleton['api']['extended-info']['optimizationwarning'] = 'Never manually edit the filters list in this file if the data is optimized! Use --groomonly to un-optimize first. Never manually edit losslesstracking.addedfilters or losslesstracking.removedfilters; data loss is guaranteed if you do.'
  skeleton['api']['extended-info']['thisfileoptimized'] = False
  skeleton['lastUpdated'] = runcontrol['nowstringzulu']
  skeleton['exceptions'] = []
  skeleton['filters'] = []
  skeleton['extended-data']['excludefromfilters'] = []
  skeleton['extended-data']['deltasinceprev'] = []
  # list of dictionaries
  skeleton['extended-data']['regexsubstringsubs'] = []
  skeleton['extended-data']['regexsubstringsubs'].append(dict())
  # list of dictionaries
  skeleton['extended-data']['regexsummarizations'] = []
  skeleton['extended-data']['regexsummarizations'].append(dict())
  skeleton['extended-data']['losslesstracking']['addedfilters'] = []
  skeleton['extended-data']['losslesstracking']['removedfilters'] = []
  runcontrol['log'].debug('output JSON data structure initialized')
  return skeleton


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
  runcontrol['log'].debug('primary input JSON loading')
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
    return pjsondata


def FindLoadSecondaryJSON(runcontrol:dict)->dict:
  '''This downloads or reads from file updated filters.

  Notes:
  !! hard coding note !! - http header info is hard coded and formatted esxpecially for https://fsrm.experiant.ca needs
  either downloads via http or reads from file
  file load uses specific file name passed in, no globbing

  Inputs:
  runtime control baton

  Outputs:
  returns - dictionary loaded with secondary JSON data
  '''

  runcontrol['log'].debug('secondary input JSON loading')
  if not runcontrol['cmdlineargs'].localsecondaryjson:
    runcontrol['log'].debug('secondary JSON data downloading from ' + runcontrol['cmdlineargs'].url)
    urlopener = urllib.request.build_opener()
    # hard coded header info, may need to be tweaked someday, Experiant definitely won't work without this
    urlopener.addheaders = [('User-Agent','Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1941.0 Safari/537.36')]
    urllib.request.install_opener(urlopener)
    try:
      with urllib.request.urlopen(runcontrol['cmdlineargs'].url) as openedURL:
        rawdatadownload = openedURL.read()
        encoding = openedURL.info().get_content_charset('utf-8')
        sjsondata = json.loads(rawdatadownload.decode(encoding))
    except json.decoder.JSONDecodeError:
      runcontrol['log'].error('unable to parse secondary JSON data downloaded from ' + runcontrol['cmdlineargs'].url)
      raise
    except:
      runcontrol['log'].error('secondary input JSON download failed, consider using a local secondary JSON data file instead')
      raise
    else:
      runcontrol['log'].info('secondary input JSON downloaded from: ' + runcontrol['cmdlineargs'].url)
      return sjsondata
  else: # else use a local JSON file
    runcontrol['log'].debug('loading secondary JSON from file ' + runcontrol['secondaryjsonpath'].name)
    try:
      with open(runcontrol['secondaryjsonpath'], 'r', encoding='utf-8') as infilejson:
        sjsondata = json.load(infilejson)
    except json.decoder.JSONDecodeError:
      runcontrol['log'].error('unable to parse secondary JSON data from ' + runcontrol['secondaryjsonpath'].name)
      raise
    except(OSError):
      runcontrol['log'].error('secondary input JSON file found - specified file: '+runcontrol['secondaryjsonpath'].name)
      raise
    except Exception:
      runcontrol['log'].error('unhandled exception reading secondary input JSON file: '+runcontrol['secondaryjsonpath'].name)
      raise
    else:
      runcontrol['log'].info('secondary input JSON read from file: ' + runcontrol['secondaryjsonpath'].name)
      return sjsondata


def CombinedDataProcessing(opjson:dict, pconstjsondata:dict, sconstjsondata:dict, runcontrol:dict)->None:
  '''This handles all data processing work EXCEPT advanced optimizations.

  Notes:
  this processing will move filters between various keys in the data dictionary, but the filters are never lost, entire process is lossless
  
  Inputs:
  initialized output JSON dictionary
  primary input JSON dictionary
  secondary input JSON dictionary
  runtime control baton

  Outputs:
  output JSON dictionary
  '''
  runcontrol['log'].debug('merging and processing all data')

  if pconstjsondata['api']['extended-info']['extended-version'] != opjson['api']['extended-info']['extended-version']:
    if pconstjsondata['api']['extended-info']['extended-version'] == 3:
      #update JSON data, simply copy allowed to new attribute, only a name update - no transform, we'll just leave the old key alone because we'll never use it again
      pconstjsondata['extended-data']['excludefromfilters'] = pconstjsondata['extended-data']['allowed']
      del(pconstjsondata['extended-data']['allowed'])
      pconstjsondata['extended-data']['losslesstracking'] = pconstjsondata['extended-data']['opttracking']  # shallow copy is fine here
      del(pconstjsondata['extended-data']['opttracking'])
    else:
      runcontrol['log'].error('primary input JSON format is an unsupported version ' + str(opjson['api']['extended-info']['extended-version']) +' format')
      raise ValueError

  # from this point forward we assume that the data is in the latest JSON format
  # copy the data that is never changed by this program, it is user edited in the JSON and static here
  # we need allowed, exceptions, both reggy 
  opjson['extended-data']['excludefromfilters'].extend(pconstjsondata['extended-data']['excludefromfilters'])
  opjson['extended-data']['excludefromfilters'].sort()
  opjson['exceptions'].extend(pconstjsondata['exceptions'])
  opjson['exceptions'].sort()
  opjson['extended-data']['regexsubstringsubs'] = copy.deepcopy(pconstjsondata['extended-data']['regexsubstringsubs']) # nested data, use deepcopy
  opjson['extended-data']['regexsummarizations'] = copy.deepcopy(pconstjsondata['extended-data']['regexsummarizations']) # nested data, use deepcopy
  # added and removed filters will be pulled from pconstjsondata, we don't need copies because it is dynamically created with each pass if optimized

  if not runcontrol['cmdlineargs'].reloadfromsecondaryfilters:
    try:
      # dedupe the filters, someone may have added something to the filters manually and dupes will wreck the unwind
      opjson['filters'].extend(list(dict.fromkeys(pconstjsondata['filters'])))
      runcontrol['log'].info(str(len(pconstjsondata['filters'])) + ' filters read from primary input JSON')
    except KeyError:
      runcontrol['log'].error('no filters attribute in input JSON data - mandatory attribute, may be empty but must exist')
      raise
    except:
      runcontrol['log'].error('unexpected error in primary JSON filters data')
      raise
    else:
      # unwind previous optimizations, if any
      if len(pconstjsondata['extended-data']['losslesstracking']['removedfilters']) > 0 :
        # defensively dedupe the added filters, shouldn't need to do this UNLESS someone edits the file, dupes will blow up
        localaddedlist = list(dict.fromkeys(pconstjsondata['extended-data']['losslesstracking']['addedfilters']))
        # remove previously added optimized filters first, then put original filters back, filters list will be lossless of original values
        # un-add the added filters first in case there was a collision with the removed filters, assumes filters list was deduped
        for filterstring in localaddedlist:
          opjson['filters'].remove(filterstring)
        # un-remove - now restore all previously removed filters, includes allowed filters that were removed
        opjson['filters'].extend(pconstjsondata['extended-data']['losslesstracking']['removedfilters'])
        opjson['filters'] = (list(dict.fromkeys(opjson['filters'])))
  else:
    runcontrol['log'].warning('-refreshsecondary option specified, primary JSON filters will not be used, all other primary JSON data is carried over')

  # merge with secondary if necessary
  if not runcontrol['cmdlineargs'].groomingonly:
    # we can't ask forgiveness for this one, empty filters list would fail silently
    try:
      # two tests in one, the -1 index will blow up if the list is empty, a little sanity checking to be sure input is a list of strings too
      if not type(sconstjsondata['filters'][-1]) == str: pass
    except: # I expect KeyError,IndexError for non-existent and empty respectively, possibly TypeError too, but we'll intentionally catch everything and let it traceback
      runcontrol['log'].error('no secondary filters found or invalid secondary filters found, check secondary input JSON data')
      raise
    opjson['filters'].extend(sconstjsondata['filters'])
    opjson['api']['extended-info']['SecondaryLastUpdated'] = sconstjsondata['lastUpdated']
    runcontrol['log'].info(str(len(sconstjsondata['filters'])) + ' secondary JSON filters merged')
  else:
    runcontrol['log'].debug('secondary JSON filters not used due to -groomingonly option')

  # finally dedupe our newly built filters list
  opjson['filters'] = list(dict.fromkeys(opjson['filters']))
  runcontrol['log'].info(str(len(opjson['filters'])) + ' merged and deduped filters pre-optimization')
  
  # process allowed fspecs, remove from filters, add to removed
  for filterstring in opjson['extended-data']['excludefromfilters']:
    if filterstring in opjson['filters']:
      opjson['extended-data']['losslesstracking']['removedfilters'].append(filterstring)
      opjson['filters'].remove(filterstring)
  runcontrol['log'].info(str(len(opjson['filters'])) + ' filters after processing allowed fspecs')

  # OPP TEE M'EYES optimize if requested
  if runcontrol['cmdlineargs'].optimizefilters:
    FiltersOptimization(opjson, runcontrol)
    opjson['api']['extended-info']['thisfileoptimized'] = True

  # wrap it up
  opjson['filters'].sort()
  opjson['api']['file_group_count'] = len(opjson['filters'])
  # in case allowed fspecs were used we should sort the removed filters
  opjson['extended-data']['losslesstracking']['removedfilters'].sort()
  runcontrol['log'].info(str(len(opjson['filters'])) + ' filters for final ouput (post-optimization if any)')

  # generate a list of filters that are new since the last run
  pconstjsondata = copy.deepcopy(pconstjsondata) # refresh our scratch local copy because our working copy has been polluted - not anymore, we can get rid of this
  if runcontrol['cmdlineargs'].reloadfromsecondaryfilters: pconstjsondata['filters'] = [] # special case, --reloadfromsecondaryfilters blindly reloads new list of filters
  for filterstring in opjson['filters']:
    if filterstring not in pconstjsondata['filters']:
      opjson['extended-data']['deltasinceprev'].append(filterstring)
  runcontrol['log'].info(str(len(opjson['extended-data']['deltasinceprev'])) + ' new and/or modified filters added filters since last run')

  # check if changes to filters, exceptions, and allowed lists, if no changes then we don't need to write new output files, set the flag to dry run
  # if grooming only (which ignores secondary inputs) then we must write
  # if we're forcing output of new JSON then we must write, the user may just want a new datestamp or whatever
  # we could simplify this boolean, but let's shoot for clarity instead (non-inverted output NAND)
  if (not runcontrol['cmdlineargs'].groomingonly) and (not runcontrol['cmdlineargs'].force):
    if (opjson['filters'] == pconstjsondata['filters']) and (opjson['exceptions'] == pconstjsondata['exceptions']) and (opjson['extended-data']['excludefromfilters'] == pconstjsondata['extended-data']['excludefromfilters']):
      runcontrol['log'].warning('Data files will not be written - new filters, allowed, and exceptions all match original input')
      runcontrol['cmdlineargs'].dryrun = True
  runcontrol['log'].debug('data processing completed')
  

def FiltersOptimization(jsondat:dict,runcontrol:dict)->None:
  '''This handles advanced optimizations only.

  Notes:
  this optimization will move filters between various keys in the data dictionary, but the filters are never lost, entire process is lossless
  optimizations are only as good as the regex strings found in the JSON data, we do our best to tell the user about the bad ones
  during optimization there may be a lot messages generated, they're OK, optimizations can produce a lot of duplicates and rejections
  the substring optimization only matches once on the the first regex it hits on, the rest will be ignored, to do in the future perhaps
    same story for the whole string summarizations but they should only match once anyway if the regex was done right
  !! hard coding note !! - the regex compilation is hard coded to ignore case
  
  Inputs:
  complete JSON dictionary that only needs to be optimized
  runtime control baton

  Outputs:
  optimized JSON dictionary
  '''
  runcontrol['log'].info('applying optimizations')
  runcontrol['log'].debug('optimizations note: rejections are normal, reevaluate regex as needed especially "stardotstar-prevent", "already-in-filters" can usually be ignorned')
  regexsumsmatchinglist = [] # a list of tuples (pre-compiled regex, regex string, summarization string)
  regexsubstringsubsmatchinglist = [] # a list of tuples (pre-compiled regex, regex string, subtitution substring)
  killlist = [] # for filters that are just getting removed from the list, we can't nuke them inside the optimzation loop so build a list and do it last

  # compile regex summarizations and build tuples
  # !! note: skips invalid regex strings, it is safe to fail any string since this is an optimization feature
  for reggydict in jsondat['extended-data']['regexsummarizations']:
    for key in reggydict:
      try:
        regexsumsmatchinglist.append((re.compile(key, re.IGNORECASE),key, reggydict[key]))
      except:
        runcontrol['log'].warning('invalid regex string - skipping summarazation for: ' + key)

  # compile regex substring substitutions and build tuples
  # !! note: skips invalid regex strings, it is safe to fail any string since this is an optimization feature
  for reggydict in jsondat['extended-data']['regexsubstringsubs']:
    for key in reggydict:
      try:
        regexsubstringsubsmatchinglist.append((re.compile(key, re.IGNORECASE),key, reggydict[key]))
      except:
        runcontrol['log'].warning('Invalid regex string. Skipping summarazation for: ' + key)

  # this for loop doesn't modify the jsondat['filters'], the actual string swaps happen later
  for astring in jsondat['filters']:
    ## init  this pass ##
    #make working copy of string that may be modified at any step
    fspecstring = astring
    # control and message lists
    optflag = False # an optimization occurred
    denyopt = False # indicates a warning was generated and that the optimization was blocked/denied
    reggymatches = [] # list of optimizations performed, for verbose output
    optwarnings = [] # list of warnings generated for denial messages

    ## optimiztions ##
    # make substring substitutions, !!! substring matches only first occurance !!!
    for reggy in regexsubstringsubsmatchinglist:
      if reggy[0].findall(fspecstring):
        optflag = True
        fspecstring = reggy[0].sub(reggy[2],fspecstring,count=1)
        reggymatches.append(reggy[1])
    # make summarization replacments
    # NOTE: assumes wilcards and other substring replacements have already been applied, important
    for reggy in regexsumsmatchinglist: # iterates through list of tuples with regex and summarization info
      if reggy[0].findall(fspecstring):
        optflag = True
        fspecstring = reggy[2]
        reggymatches.append(reggy[1])

    ## safeties ##
    # once a denyopt has been set we can stop checking for additional reasons, very unlikely it will be more than one reason anyway
    if optflag:
      # stardotstarprevention
      if fspecstring == "*.*":
        denyopt = True
        optwarnings.append('stardotstar-prevent')
      # make sure we didn't regenerate an allowed fspec
      elif fspecstring in jsondat['extended-data']['excludefromfilters']:
        denyopt = True
        optwarnings.append('in-excludefromfilters')
      # test for optimization to same, dupe
      elif (astring == fspecstring):
        denyopt = True
        optwarnings.append('repeat-of-self')
      elif fspecstring in jsondat['filters']:
        denyopt = True
        optwarnings.append('already-in-filters')
      reggymatchesmsg = ', '.join(reggymatches)

    # if denied then tell them why
    if denyopt:
      optwarningsmsg = ', '.join(optwarnings)
      runcontrol['log'].debug(astring +' -> '+fspecstring+' optimization regected, matching regex: '+reggymatchesmsg+' reject reasons: '+optwarningsmsg)

    # if the fspec has been optimized and it didn't trigger a deny optimization
    if optflag and not denyopt:
      runcontrol['log'].debug(astring + ' >-optimized to-> ' + fspecstring + '  (matched regex: ' + reggymatchesmsg +')')
      jsondat['extended-data']['losslesstracking']['removedfilters'].append(astring)
      if len(fspecstring) > 0: # don't add if the optimization is an empty string
        jsondat['extended-data']['losslesstracking']['addedfilters'].append(fspecstring)
    # end of the optimization loop

  # only optimization uses jsondat['extended-data']['losslesstracking']['addedfilters'], if there are any items in the list then we found something to optimize
  if len(jsondat['extended-data']['losslesstracking']['addedfilters']) > 0:
    # we expect lots of dupes in the added list because one of the goals is to summarize a bunch of those filters, dedupe before we do anything
    jsondat['extended-data']['losslesstracking']['addedfilters'] = list(dict.fromkeys(jsondat['extended-data']['losslesstracking']['addedfilters']))
    jsondat['extended-data']['losslesstracking']['addedfilters'].sort()
    # sort the removed so they're pretty
    jsondat['extended-data']['losslesstracking']['removedfilters'].sort()
    # there should be no dupes in the removed list, processing the 'excludefromfilters' is not an optimization (1 to 1 relationship) and should have already been done, no need to dedupe here
    for astring in jsondat['extended-data']['losslesstracking']['removedfilters']:
      if astring in jsondat['filters']: jsondat['filters'].remove(astring)
    # now we just add the optimations and sort
    jsondat['filters'].extend(jsondat['extended-data']['losslesstracking']['addedfilters'])
    jsondat['filters'].sort()

  # optimization leaves lots of dupes in the filters and addedfilters, dedupe now that we're done
  jsondat['filters'] = list(dict.fromkeys(jsondat['filters']))
  jsondat['filters'].sort()


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
    with open(runcontrol['opjsonpath'], 'w', encoding='utf-8') as outfilejson:
      outfilejson.write(jsondatstring)
  except OSError:
    runcontrol['log'].error('failed to write ouput JSON file ' + str(runcontrol['opjsonpath']))
    raise
  except:
    runcontrol['log'].error('unhandled exception writing ouput JSON file ' + str(runcontrol['opjsonpath']))
    raise
  else:
    runcontrol['log'].info('JSON ouput data written to file: ' + runcontrol['opjsonpath'].name)


def WriteAncillaryTextFiles(opjson:dict, runcontrol:dict)->None:
  '''This writes the ancillary text files. These files only contain the 'filters'.

  Notes:
  writes only the filters from the output JSON data
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
  try:
    with open(runcontrol['opfiltersoneperlnpath'], 'w', encoding='utf-8') as outfiletext:
      for listitem in opjson['filters']:
        outfiletext.write(listitem+'\n')
  except OSError:
    runcontrol['log'].error('error writing ancillary text file ' + runcontrol['opfiltersoneperlnpath'].name)
  except:
    runcontrol['log'].error('unhandle exception writing ancillary text file ' + runcontrol['opfiltersoneperlnpath'].name)
  else:
    runcontrol['log'].info('ancillary text file written to file ' + runcontrol['opfiltersoneperlnpath'].name)

  try:
    with open(runcontrol['opfiltersPSlistpath'], 'w', encoding='utf-8') as outfiletext:
      # we're going to kludge this just so I don't have to deal with getting the actual index
      # this list has only unique entries so we'll string match to find the end
      for listitem in opjson['filters']:
        if (listitem != opjson['filters'][-1]):
          outfiletext.write('"'+listitem+'"'+',')
        else: # no trailing comma
          outfiletext.write('"'+listitem+'"')
  except OSError:
    runcontrol['log'].error('error writing ancillary text file ' + runcontrol['opfiltersPSlistpath'].name)
  except:
    runcontrol['log'].error('unhandle exception writing ancillary text file ' + runcontrol['opfiltersPSlistpath'].name)
  else:
    runcontrol['log'].info('ancillary text written to file: ' + runcontrol['opfiltersPSlistpath'].name)



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
  # find all the matching input primary JSON files and select the newest
  infilelist = list(runcontrol['workdirpath'].glob(runcontrol['jsonfnamewildcard']))
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

  # text files only rotated if text files were created in this run
  if runcontrol['cmdlineargs'].ancillarytextfiles:
    for akey in runcontrol['opfilterstextrotatekeys']:
      # search and delete
      infilelist = list(runcontrol['workdirpath'].glob(runcontrol[akey]))
      infilelist.sort()
      for n in range(0, len(infilelist)-runcontrol['cmdlineargs'].rotatefilescount):
        try:
        # we're hard coding rw stat on the file, the user has implicitly authorized deletion by not setting --rotatefilescount to zero and specifying --ancilarytextfiles
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
  # skeleton gets written to file, no other processing is required
  if not runtimecontrol['cmdlineargs'].skeletononly:
    if runtimecontrol['cmdlineargs'].groomingonly:
      CombinedDataProcessing(opjsondata, FindLoadPrimaryJSON(runtimecontrol), None, runtimecontrol)
    else:
      CombinedDataProcessing(opjsondata, FindLoadPrimaryJSON(runtimecontrol), FindLoadSecondaryJSON(runtimecontrol), runtimecontrol)
  
  # write all output files
  if not runtimecontrol['cmdlineargs'].dryrun:
    WriteOpJSON(opjsondata, runtimecontrol)
    if runtimecontrol['cmdlineargs'].ancillarytextfiles:
      WriteAncillaryTextFiles(opjsondata, runtimecontrol)
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
