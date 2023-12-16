r'''
This module can be used in 3 modes:
    1) Run the script with download argument:  Downloads IPAM data from IPAM API (Owner April), re-orgnizes in a format for efficient searching
    and saves into a folder as a Zipped Json file. -d param can be used to specify the folder
    to download gz files (default: \\FMS-DBM-GNM-A3\RVSHARE\IntelIPAMRanges).
      On Windows: Credentials for API should be specified in keyring using rv.crtypt:
            cr.keyring_set('IPAM_API', 'USER', <username>)
            cr.keyring_set('IPAM_API', 'PASSWORD', <password>)
      On Linux, set the credentials in environment vars:
            export IPAM_API_USER="username"
            export IPAM_API_PASSWORD="password"
      Contact Ram Varra or April Averit for API Credentials info.

    2) Module import: Use IntelIPAM() constructor to create an instance. In this mode, it will load latest
    IPAM Range (zipped json) file that was created in download mode.  The object's lookup_ip() provides look up functionality.
    In this mode, IPAM api will not be accessed, hence credential setup is not needed.  The directory where
    the gz files are downloaded should be specified in the constructor of IntelIPAM()

    3) Run the script without any argument: Runs unit tests on lookup_ip().

The IPAM JSON File is organized as below and compressed with GZIP (.gz).  INFO dict will be returned for lookup.

# master_block
{
    "4": [ # list of subnet_blocks sorted by NUM in its range block for IPV4
        {
            "10": [ # list of subnets sorted of BEGIN_I
                { 'BEGIN_I': 10000, 'END_I': 10010,'INFO': {...}},
                {'BEGIN_I': 20000, 'END_I': 20010,'INFO': {...}},
            ]
        },
        {
            "11": [
                { 'BEGIN_I': 30000, 'END_I': 30011,'INFO': {...} },
                {'BEGIN_I': 40000, 'END_I': 40011,'INFO': {...} }
            ]
        }
    ],
    "6": [ ... ] # same as in V4
}

TBD: For GeoCodes, Use reports here (My Reports - BuildingReport)
http://tririga.intel.com/html/en/default/platform/mainpage/mainpage.jsp

'''
import os, sys, re
import json
import logging
import ipaddress
import datetime
import gzip
import socket
import time
from pprint import pprint, pformat

import logutil

# ---------------------------------------------------------------------------------------------------------------------
class IntelIPAM:
    # REST API end point to fetch all ranges
    _IPAM_API_URL = 'https://ipam.intel.com/mmws/api/ranges'

    # Intel CERT File for https client.  Get from https://pki.intel.com
    _CERT_FILE = 'IntelSHA256RootCA-Base64.crt'


    # file containing SiteName to lat/lon mapping.  This file is manually created by Ram using Google Maps.
    # It will need to be udpated on going basis when new Sites are added to IPAM. We will generate
    # email notifications if we new sites are addeded that do not have defined geo map.
    _GEO_CODE_JSON_FILE = 'IPAM_GeoCode.json'

    # Ignore these sites - no geo location map expected for these.
    _IGNORE_MISSING_SITES = ['Missing from Corp DB', 'Virtual, Americas']


    # EMAIL notification will be sent to this list if there are missing sites
    # the _GEO_CODE_JSON_FILE in rv3 needs to be updated to include the new sites.
    # use Google maps to find lat/lon
    _MISSING_GEO_CODE_EMAIL = ['ram.r.varra@intel.com']

    # Keystore subject name for USER and PASSWORD. Used when running in downloa mode.
    # Use below to set the keyring values. Contact April for information on what Credentials
    # are needed. Currently any AD account will work (e.g. AMR\sys_esetl):
    #            import rv.crypt
    #            cr = rv.crypt.Crypt()
    #            cr.keyring_set('IPAM_API', 'USER', '****')
    #            cr.keyring_set('IPAM_API', 'PASSWORD', '****')

    # raise exception if there more than this many missing sites
    _MAX_ALLOWED_MISSING_GEO_CODE_SITES = 2

    # in windows - uses this service name, USER, PASSWORD from keyring
    # on UNIX: ENV vars with this prefix _USER, _PASSWORD
    _IPAM_API_CREDS_KEYSTORE = 'IPAM_API'

    # minimum number of ranges expected from IPAM - for data quality check
    _MINIMUM_RANGES_EXPECTED = 20000

    # Json/zip files should start with this prefix and end with .json or .zip (case sensitive)
    _JSON_FILE_PREFIX = 'Intel_IPAM_Ranges-'

    # default location to store/fetch IPAM range zipped json files
    _IPAM_RANGE_JSON_DIR = r'\\FMS-GNM-DBM-A16\RVSHARE\IntelIPAMRanges'

    # Split "INF* (Infrastructure (Backbone, Distribution))" into
    # into Code: INF Name: Infrastructure (Backbone, Distribution)
    # removes any training stars after code
    _CODE_NAME_SPLITTER_REGEX = re.compile(r'''
      (?P<Code>[A-Z\d_-]+)       # building code
      [*\s]*                     # one or more spaces or *
      (\((?P<Name>.*)\))?        # optional  name in paranethesis
      ''', re.X)

    #MAIL Configuration to send email notifications
    _MAIL_CONFIG = {
        'EMAIL_FROM': 'ram.r.varra@intel.com',
        'FATAL_TO': 'ram.r.varra@intel.com',
        'SMTP_SERVER': 'smtp.intel.com'
    }

    # ---------------------------------------------------------------------------------------------------------------------
    def __init__(self, source_dir=None):
        '''
        source: 'api', load from REST API.  Credentials will be read from keystore 'IPAM_API'
        source: directory: load from the latest file in the folder.
        source: None:  load from latest file in _IPAM_RANGE_JSON_DIR
        source: file: load from the file specified
        '''
        self._master_block = None
        self._ipam_file = None
        if source_dir == 'api':
            self._init_from_api()
        else:
            self._init_from_json_gz_file(source_dir)

        # ensure the master block is sorted
        self.validate()
        logging.info("Done")

    # ---------------------------------------------------------------------------------------------------------------------
    def _matchng_files(self, source_dir):
        '''
        return a sorted list of (mtime, file_path) tuples that match with prefix and ends with .gz
        from source directory - most recent files first.
        '''
        def fn_match(f):
            return f.startswith(self._JSON_FILE_PREFIX) and f.endswith('.gz')

        #file_infos = ((f.stat().st_mtime, f.path) for f in os.scandir(source_dir) if fn_match(f.name))
        file_paths = [os.path.join(source_dir, file_name) for file_name in os.listdir(source_dir) if fn_match(file_name)]
        file_infos = [(os.path.getmtime(fp), fp) for fp in file_paths]
        return sorted(file_infos, reverse=True)

    # ---------------------------------------------------------------------------------------------------------------------
    def _init_from_json_gz_file(self, source_dir):
        '''
        see __init__() for handling of source
        '''
        if source_dir is None:
            source_dir = self._IPAM_RANGE_JSON_DIR

        if not os.path.isdir(source_dir):
            raise Exception("Source '{}' must be dir containing '{}*.gz' files".format(source_dir, self._JSON_FILE_PREFIX))

        json_file_infos = self._matchng_files(source_dir)
        if len(json_file_infos) == 0:
            raise Exception(r"No  files matching prefix '{}*.gz' pattern in dir: {}".format(self._JSON_FILE_PREFIX, source_dir))
        json_gz_file = json_file_infos[0][1]

        logging.info("Loading from file: {}".format(json_gz_file))
        with gzip.open(json_gz_file, 'rt') as zfd:
            logging.info("Loading Range file from %s", json_gz_file)
            self._master_block = json.load(zfd)
        self._ipam_file = json_gz_file

    # ---------------------------------------------------------------------------------------------------------------------
    def get_ipam_file(self):
        return self._ipam_file

    # ---------------------------------------------------------------------------------------------------------------------
    def _get_api_creds(self):
        '''
        returns (user, password) tuple from keyring. See _IPAM_API_CREDS_KEYSTORE
        documentation on setting the keyring.
        '''
        import env_vars
        return env_vars.IPAM_API_USER, env_vars.IPAM_API_PASSWORD

    # ---------------------------------------------------------------------------------------------------------------------
    def _init_from_api(self):
        '''
        Load IPAM range data from API and build sorted master_block structure.
        '''
        import requests

        # build data structure - json keys are strings, hence all keys used for lookup will be str
        self._master_block = {
            "4": [],
            "6": []
        }

        if not os.path.exists(self._GEO_CODE_JSON_FILE):
            raise Exception("GeoCode Json file {} not found".format(self._GEO_CODE_JSON_FILE))

        if not os.path.exists(self._CERT_FILE):
            raise Exception("SSL CERT file  {} not found".format(self._CERT_FILE))

        #api_creds = tuple(os.environ.get(ev) for ev in self._IPAM_API_CREDS_ENV_VARS)
        api_creds = self._get_api_creds()

        try:
            self._geo_code_map = json.load(open(self._GEO_CODE_JSON_FILE))
        except json.JSONDecodeError as ex:
            raise Exception("Failed to read geo_code_map from {}: {}".format(self._GEO_CODE_JSON_FILE, ex))

        # track the any new missing geocode SiteNames, email these for updating the
        # _GEO_CODE_JSON_FILE
        self._missing_geocode_sites = set()
        self._missing_status_ranges = list()

        # load the ipam ranges
        logging.info("Loading ipam ranges")

        start_ts = time.time()
        resp = requests.get(self._IPAM_API_URL, auth=api_creds, verify=self._CERT_FILE)
        if resp.status_code != 200:
            raise Exception("IPAM API request {} failed. Response: {}".format(self._IPAM_API_URL, resp))

        logging.info("API Returned in {:.1f} secs".format(time.time() - start_ts))

        try:
            result = resp.json()
        except Exception as ex:
            raise Exception("Failed to parse IPAM API json response: {}".format(ex))

        if 'result' not in result or 'ranges' not in result['result']:
            raise Exception("IPAM API response does not have required keys: [result][ranges]")

        ranges = result['result']['ranges']

        if not isinstance(ranges, list):
            raise Exception("IPAM API response contains non list type: [result][ranges] - {}".format(type(ranges)))

        logging.info("IPAM API returned {} ranges".format(len(ranges)))

        # ensure we have atleast _MINIMUM_RANGES_EXPECTED ranges
        if len(ranges) < self._MINIMUM_RANGES_EXPECTED:
            raise Exception("IPAM API returned less than minimum expected ranges: {} vs {}".format(len(ranges),
                                                                                                   self._MINIMUM_RANGES_EXPECTED))
        logging.info("Building and sorting master block")
        self._build_master_block(ranges)
        self._sort_master_block()

        me = socket.gethostname()

        # log missing Sites
        if self._missing_geocode_sites:
            site_list = ",".join("'{}'".format(s) for s in self._missing_geocode_sites)
            msg = "Missing geocode sites = {}".format(site_list)
            msg += "\nUpdate the Geocode file in rv3 and run rv_install.py with these sites."
            logging.error(msg)
            #misc.send_mail(subject="{}: Missing Geocode sites IPAM data".format(me), content=msg, email_to=self._MISSING_GEO_CODE_EMAIL)

        if self._missing_status_ranges:
            msg = "IPAM data has {} ranges with missing ['customProperties']['Status']\n".format(len(self._missing_status_ranges))
            range_list = "\n".join(ri['name'] for ri in self._missing_status_ranges)
            msg += "\nList of ranges that have this issue: \n{}".format(range_list)
            msg += "\nContact IPAM owner and get this issue fixed."
            #logging.error(msg)
            #misc.send_mail(subject="{}: Missing Status field in IPAM data".format(me), content=msg, email_to=self._MISSING_GEO_CODE_EMAIL)

        #if len(self._missing_geocode_sites) > self._MAX_ALLOWED_MISSING_GEO_CODE_SITES:
        #    raise Exception("Missing geocode sites is more than {}. Acutal {}".format(self._MAX_ALLOWED_MISSING_GEO_CODE_SITES,
        #        len(self._missing_geocode_sites)))

        overlap_list = self.find_overlaps()
        if  overlap_list:
            msg = "Overlapping ranges found in IPAM - {} ranges with overlaps".format(len(overlap_list))
            for ol in overlap_list:
                logging.info("Overlap Range Info: {}".format(ol))
            msg += "\nCheck the log for details"
            #misc.send_mail(subject=msg, content=msg, email_to=self._MISSING_GEO_CODE_EMAIL)

    # ------------------------------------------------------------------------------------------------------------------
    def find_overlaps(self):
        overlap_list=[]
        def _find_overlaps_in_block(subnet_block):
            range_size = list(subnet_block.keys())[0]
            block = list(subnet_block.values())[0]
            r2_g = iter(block)
            next(r2_g)
            for r1, r2 in zip(block, r2_g):
                if r1['IP_END'] >= r2['IP_START']:
                    overlap_list.append('CUR_END_AFTER_NEXT_START', range_size, r1, r2)
                if r2['IP_START'] <= r1['IP_END']:
                    overlap_list.append('CUR_START_BEFORE_PREV_END', range_size, r1, r2)

        for ipv in ['4', '6']:
            mbv = self._master_block[ipv]
            for mbv_subnet_block in mbv:
                _find_overlaps_in_block(mbv_subnet_block)
        return overlap_list

    # ------------------------------------------------------------------------------------------------------------------
    def _build_master_block(self, ranges):
        for ri in ranges:
            if not self._is_valid_range(ri):
                continue
            rec, version = self._convert_api_rec(ri)
            self._add_to_master_block(rec, version)

    # ------------------------------------------------------------------------------------------------------------------
    def _range_info(self, subnet_range):
        '''
        Calculates START, END and NUMBBER addresses for IP Range.  Processes ranges expressed as
        ADDR1-ADDR2 (e.g. 10.24.164.0-10.24.171.255).
        :param sn: Range string.
        :return: tuple ({'IP_START': <int>, 'IP_END': <int>}, <str-"4" ro "6">)
        '''
        if '/' in subnet_range:
            n = ipaddress.ip_network(subnet_range)
            ns = n.network_address
            ne = ns + n.num_addresses - 1
        elif '-' in subnet_range:
            # 10.24.164.0-10.24.171.255
            start, end = subnet_range.split('-')
            ns, ne = ipaddress.ip_address(start), ipaddress.ip_address(end) # validate these are IP addresses
        else:
            raise Exception("Invalid range: {}".format(subnet_range))

        return {'IP_START': int(ns), 'IP_END': int(ne)}, str(ns.version)

    # ---------------------------------------------------------------------------------------------------------------------
    def _is_valid_range(self, ri):
        if ri['name'] == '::/0' or ri['name'].startswith('0.0.0.0/'):
            return False
        if not (cp := ri.get('customProperties')):
            raise Exception(f"Range {ri} does not have a customProperty attribute".format(ri))
        if not (status := cp.get('Status')):
            self._missing_status_ranges.append(ri)
            return False

        return status in ('Assigned', 'Discovered', 'Logical-group')

    # ---------------------------------------------------------------------------------------------------------------------
    def _convert_api_rec(self, ri):
        '''
        Convert a range record returned by IPAM API to format that will be used for IPAM Lookup. Adds site location (lat/lon)
        by looking up SiteName in Geo_Code map
        param ri:  dict, range record from IPAM API
        return si: tuple(dict ofconverted subnet record, ip_version string)
        '''

        ri_cp = ri['customProperties']
        info = {'Range': ri['name'].strip()}

        for f in ['Region', 'Country', 'Title', 'SiteName', 'SiteCode']:
            if f in ri_cp:
                info[f] = ri_cp[f].strip()

        for f in ['Building', 'Environment', 'Function']:
            key = 'BuildingCode' if f == 'Building' else f
            v = ri_cp.get(key, '').strip()
            if v:
                info[f+'Code'] = v
                m = re.match(self._CODE_NAME_SPLITTER_REGEX, v)
                if m:
                    info[f+'Code'] = m.group('Code')
                    info[f] =  m.group('Name')

        for f in ['SiteName', 'SiteCode', 'Region', 'Country', 'Title', 'Function', 'Environment']:
            v = info.get(f)
            if v:
                info[f] = v.replace('*', '')


        info['VPN'] = info.get('FunctionCode') == 'VPN'

        # perform Geocode lookup, add to missing set if not found
        site_name = info.get('SiteName')
        if site_name:
            loc = self._geo_code_map.get(site_name)
            if loc:
                info['SiteLoc'] = loc
            else:
                if site_name not in self._IGNORE_MISSING_SITES:
                    self._missing_geocode_sites.add(site_name)

        # add range info
        rec, version = self._range_info(info['Range'])
        rec['INFO'] = {k:v for k, v in info.items() if v is not None}

        return rec, version

    # ---------------------------------------------------------------------------------------------------------------
    def _add_to_master_block(self, rec, ip_version):
        '''
        Add a range record to master block, at right range_size location
        '''
        subnet_blocks = self._master_block[ip_version]
        ip_begin, ip_end = rec['IP_START'], rec['IP_END']
        range_size = ip_end - ip_begin + 1

        # find the range block that has these this range by size
        subnet_block = [sb for sb in subnet_blocks if range_size in sb]
        if len(subnet_block) > 0:
            subnet_block = subnet_block[0]
        else:
            # we are using integer range size as key for subnet_block.
            # json will output it as string key, however, we will need to lookup
            # the block by key during the lookup process, hence we leave it as int
            # since we can sort using ints rather converting them from str to int
            subnet_block = {range_size: []}
            subnet_blocks.append(subnet_block)
        subnet_block[range_size].append(rec)

    # ---------------------------------------------------------------------------------------------------------------
    def _sort_master_block(self):
        # sort the master_block for binary search
        for _, subnet_blocks in self._master_block.items():
            # sort each subnet_block by IP_START
            for subnet_block in subnet_blocks:
                for _, range_list in subnet_block.items():
                    range_list.sort(key=lambda x: x['IP_START'])

            # sort subnet_blocks by range size - only key
            subnet_blocks.sort(key=lambda x: list(x.keys())[0])

    # ---------------------------------------------------------------------------------------------------------------
    def _write_gz_file(self, json_gz_file):

        # write to .tmp and rename to .zip - to avoid the loaders reading incomplete files.
        tmp_file = json_gz_file + '.tmp'
        logging.info("Writing compressed gz json output to : {}".format(json_gz_file))
        with gzip.open(tmp_file, 'wt') as zfd:
            json.dump(self._master_block, zfd)
        os.rename(tmp_file, json_gz_file)
        assert os.path.exists(json_gz_file), "Failed to move {} to {}".format(tmp_file, json_gz_file)
        logging.info("Completed output to : {}".format(json_gz_file))

    # ---------------------------------------------------------------------------------------------------------------
    def write_json_gz(self, dest_dir=None, keep=3):
        '''
        Write master_block to file in dest_dir in gz format.
        dest_dir: Write to zipped json file. The file will have _JSON_FILE_PREFIX and
        current date time stamp in file name.  Default _IPAM_RANGE_JSON_DIR folder.
        keep: # of recent files to keep in the dest_dir. All older files will be deleted.
        '''
        if dest_dir is None:
            dest_dir = self._IPAM_RANGE_JSON_DIR

        f_base = "{}{:%Y-%m-%d_%H-%M-%S}.gz".format(self._JSON_FILE_PREFIX, datetime.datetime.now())
        json_gz_file = os.path.join(dest_dir, f_base)
        self._write_gz_file(json_gz_file)

        # purge old files
        logging.info("Purging old files in {}".format(dest_dir))
        file_infos = self._matchng_files(dest_dir)
        for _, fn in file_infos[keep:]:
            logging.info("Deleting old file: {}".format(fn))
            os.remove(fn)
            assert not os.path.exists(fn), "Failed to remove file: {}".format(fn)

    # ---------------------------------------------------------------------------------------------------------------
    def _is_sorted(self, s):
        '''
        Test if a sequence is ascending sorted order.
        s: list or generator of a sequence.
        '''
        s2 = iter(s)
        next(s2) # advance by 1.
        return all(i1 <= i2 for i1, i2 in zip(s, s2))
    # ---------------------------------------------------------------------------------------------------------------
    def validate(self):
        '''
        check if master block is fully sorted
        '''
        for ip_version, subnet_blocks in self._master_block.items():
            range_size_list = [int(list(blocks_dict.keys())[0]) for blocks_dict in subnet_blocks]
            if not self._is_sorted(range_size_list):
                raise Exception("IPV{} Range sizes are not in sorted order: {}".format(ip_version, range_size_list))

            for blocks_dict in subnet_blocks:
                for range_size, blocks in blocks_dict.items():
                    start_sequence = (b['IP_START'] for b in blocks)  # using generator to avoid memory consumption
                    if not self._is_sorted(start_sequence):
                        raise Exception("IPV{} Block for range: {} is not in ascending order".format(ip_version, range_size))

    # ---------------------------------------------------------------------------------------------------------------
    def _binary_search(self, info_list, ipa_int):
        '''
        Binary search in sorted blocks with Range IP_START .. IP_END* (inclusive)
        info_list: list of sorted Ranges. Each range should be a dict with 'IP_START', 'IP_END' as  integers
        ipa_int:  ip address to lookup (integer)
        returns: 'INFO' value of the Range dict, if found.  None if ipa_int not found.
        '''
        first = 0
        last = len(info_list) - 1
        logging.info("FIRST %s LAST %s", first, last)
        #metrics = {'ncompares': 0, 'size': len(info_list)}

        while first <= last:
            i = (first + last) // 2
            b = info_list[i]['IP_START']
            e = info_list[i]['IP_END']

            #metrics['ncompares'] += 1
            if b <= ipa_int <= e:
                return info_list[i]['INFO'] #, metrics

            if ipa_int < b:
                last = i - 1
            elif ipa_int > e:
                first = i + 1
            else:
                return None #, metrics

        return None #, metrics

     # ---------------------------------------------------------------------------------------------------------------
    def iter_block(self, ip_version):
        '''
        yield block in the order smallest range to largest range
        '''
        subnet_blocks = self._master_block[ip_version]
        for blocks_dict in subnet_blocks:
            for _, blocks in blocks_dict.items():
                yield blocks

    # ---------------------------------------------------------------------------------------------------------------
    def lookup_ip(self, ip, prefix=''):
        try:
            ipa = ipaddress.ip_address(ip)
        except ValueError:
            return None
        ipa_int = int(ipa)
        for blocks in self.iter_block(str(ipa.version)):
            result = self._binary_search(blocks, ipa_int)
            if result:
                if prefix:
                    result = {prefix+k: v for k,v in result.items()}
                return result
        return None

#-----------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    import optparse
    usage = "usage: %prog [-d|--dir dir] [-l|--log log_dir] [download]"
    log_dir = r'D:\Logs\IntelIPAM' if os.name == 'nt' else '/tmp'
    parser = optparse.OptionParser(usage)
    parser.add_option('-d', '--dir',
        default=IntelIPAM._IPAM_RANGE_JSON_DIR,
        help="directory read from or write to .gz files . Default {}".format(IntelIPAM._IPAM_RANGE_JSON_DIR))
    parser.add_option('-l', '--log',
        default=log_dir,
        help="directory to create logfiles. Default {}".format(log_dir))

    options, args = parser.parse_args()

    logutil.set_logging(log_file=options.log)

    logging.info("Starting IntelIPAM with args: %s", args)

    if len(args) > 0:
        assert args[0].lower() == 'download', "Expecting {} [download]".format(sys.argv[0])
        ipam = IntelIPAM('api')
        '''
        try:
            ipam = IntelIPAM('api')
        except Exception as ex:
            logging.error(f"IPAM Initializion for API download failed - {ex}")
            sys.exit(1)
        '''
        try:
            ipam.write_json_gz(dest_dir=options.dir)
        except Exception as ex:
            logging.error(f"IPAM write_json failed - {ex}")
            sys.exit(1)
        sys.exit(0)

    # do testing
    start_ts = time.time()
    intel_ipam = IntelIPAM(source_dir=options.dir)
    logging.info("Time to load: {:.1f} secs".format(time.time() - start_ts))

    for ip in ('10.12.86.10', '10.12.104.67', '10.13.17.12', '143.183.250.10', '198.175.123.40', '172.217.4.132'):
        res = intel_ipam.lookup_ip(ip)
        if not ip.startswith('172.'):
            assert res, "Failed to lookup: {}".format(ip)
        else:
            assert not res, "Bad result - expecting None for {} - got {}".format(ip, res)
        logging.info("{} = {}".format(ip, res if res else 'NOT_FOUND'))

    # bennch mark
    test_ranges = "198.175.123.0/24,10.254.73.0/24,172.217.4.0/24,10.12.86.0/24,10.12.104.64/29"
    logging.info("Generating Benchmark addresses")
    num_per_range = 100
    address_list = []
    for tr in test_ranges.split(','):
        n = ipaddress.ip_network(tr)
        n.num_addresses
        for i in range(max(num_per_range, n.num_addresses)):
            address_list.append(str(n.network_address + i))

    logging.info("Benchmark with {} addresses".format(len(address_list)))

    start_ts = time.time()
    for ipa in address_list:
        res = intel_ipam.lookup_ip(ipa)
    elapsed = time.time() - start_ts
    logging.info("Lookup time {:.1f} secs time per lookup: {:.3f} mill-secs".format(elapsed, 1000*elapsed/len(address_list)))

    logging.info("Verification")
    for ipa in address_list:
        res = intel_ipam.lookup_ip(ipa)
        if not ipa.startswith('172.'):
            assert res, "Failed to lookup: {}".format(ipa)
        else:
            assert res is None, "Bad match for IP {}  - should be None instead {}".format(ipa, res)
    logging.info("Verification successful")
