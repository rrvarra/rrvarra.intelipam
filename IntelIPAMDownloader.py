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
import os
import json
import logging
import ipaddress
from datetime import datetime, UTC
from pathlib import Path
import re
import gzip
import io
import time
from pprint import pprint, pformat

import requests

from secret_util import SecretUtil
from IntelIPAM import IntelIPAM

import logutil

# ---------------------------------------------------------------------------------------------------------------------
class IntelIPAMDownloader(IntelIPAM):

    # REST API end point to fetch all ranges
    _IPAM_API_URL = 'https://ipam.intel.com/mmws/api/ranges'

    # Intel CERT File for https client.  Get from https://pki.intel.com
    _CERT_FILE = Path(__file__).parent / 'IntelSHA256RootCA-Base64.crt'

    # Ignore these sites - no geo location map expected for these.
    _IGNORE_MISSING_SITES = ['Missing from Corp DB', 'Virtual, Americas']

    # Keystore subject name for USER and PASSWORD. Used when running in downloa mode.
    # Use below to set the keyring values. Contact April for information on what Credentials
    # are needed. Currently any AD account will work (e.g. AMR\sys_esetl):
    #            import rv.crypt
    #            cr = rv.crypt.Crypt()
    #            cr.keyring_set('IPAM_API', 'USER', '****')
    #            cr.keyring_set('IPAM_API', 'PASSWORD', '****')

    # in windows - uses this service name, USER, PASSWORD from keyring
    # on UNIX: ENV vars with this prefix _USER, _PASSWORD
    _IPAM_API_CREDS_KEYSTORE = 'IPAM_API'

    # minimum number of ranges expected from IPAM - for data quality check
    _MINIMUM_RANGES_EXPECTED = 20000

    # Split "INF* (Infrastructure (Backbone, Distribution))" into
    # into Code: INF Name: Infrastructure (Backbone, Distribution)
    # removes any training stars after code
    _CODE_NAME_SPLITTER_REGEX = re.compile(r'''
      (?P<Code>[A-Z\d_-]+)       # building code
      [*\s]*                     # one or more spaces or *
      (\((?P<Name>.*)\))?        # optional  name in paranethesis
      ''', re.X)

    # ---------------------------------------------------------------------------------------------------------------------
    def __init__(self):
        super().__init__(init_mb=False)

    # ---------------------------------------------------------------------------------------------------------------
    def upload_json_gz_to_af(self, af_auth: tuple[str, str], keep: int=3):
        '''
        Write master_block to file to artifactory in in gz format
        keep: # of recent files to keep in the artifactory. All older files will be deleted.
        '''

        current_af_files = self._get_af_gz_files()
        ts = datetime.now(UTC)
        filename = f"{self._IPAM_FILE_PREFIX}{ts:%Y-%m-%d_%H-%M-%S}.gz"
        url = f"{self._IPAM_AF_URL}/{self._IPAM_AF_REPO_PATH}/{filename}"
        logging.info("Uploading to %s", url)

        with io.BytesIO() as fd_bio:
            with gzip.open(fd_bio, 'wt') as fd_gz:
                json.dump(self._master_block, fd_gz)
            logging.info("GZ size %s", fd_bio.tell())
            fd_bio.seek(0)
            response = requests.put(url, auth=af_auth, data=fd_bio)
            response.raise_for_status()
            logging.info("AF upload resp: %s", response.json())
        # remove excess files
        if current_af_files:
            k = max(0, keep-1)
            logging.info("Current files: %s", current_af_files)
            for fn in current_af_files[:-k]:
                url = f"{self._IPAM_AF_URL}/{self._IPAM_AF_REPO_PATH}/{fn}"
                logging.info("Deleting %s", url)
                response = requests.delete(url, auth=af_auth)
                response.raise_for_status()

    def update_ranges(self) -> None:
        su = SecretUtil()
        ipam_api_auth = su.get_secret('KEYRING:IPAM:IPAM_API_USER'), su.get_secret('KEYRING:IPAM:IPAM_API_PASSWORD')
        af_auth = su.get_secret('KEYRING:IPAM:AF_IT_BTRM_LOCAL_USER'), su.get_secret('KEYRING:IPAM:AF_IT_BTRM_LOCAL_PASSWORD')

        self._init_from_api(ipam_api_auth)
        # ensure the master block is sorted
        self.validate()
        self.upload_json_gz_to_af(af_auth)
        logging.info("Done")

    # ---------------------------------------------------------------------------------------------------------------------
    def _init_from_api(self, api_auth: tuple[str, str]):
        '''
        Load IPAM range data from API and build sorted master_block structure.
        '''

        # build data structure - json keys are strings, hence all keys used for lookup will be str
        self._master_block = {
            "4": [],
            "6": []
        }
        if not os.path.exists(self._CERT_FILE):
            raise Exception(f"SSL CERT file  {self._CERT_FILE} not found")

        # load the ipam ranges
        logging.info("Loading ipam ranges")

        start_ts = time.time()
        resp = requests.get(self._IPAM_API_URL, auth=api_auth, verify=self._CERT_FILE)
        resp.raise_for_status()
        elapsed = time.time() - start_ts
        logging.info(f"API Returned in {elapsed:.1f} secs")

        try:
            result = resp.json()
        except Exception as ex:
            raise Exception(f"Failed to parse IPAM API json response: {ex}")

        if 'result' not in result or 'ranges' not in result['result']:
            raise Exception("IPAM API response does not have required keys: [result][ranges]")

        ranges = result['result']['ranges']

        if not isinstance(ranges, list):
            raise Exception(f"IPAM API response contains non list type: [result][ranges] - {type(ranges)}")

        logging.info("IPAM API returned %s ranges", len(ranges))

        self._missing_status_ranges = []
        # ensure we have atleast _MINIMUM_RANGES_EXPECTED ranges
        if len(ranges) < self._MINIMUM_RANGES_EXPECTED:
            raise Exception(f"IPAM API returned less than minimum expected ranges: {len(ranges)} vs {self._MINIMUM_RANGES_EXPECTED}")
        logging.info("Building and sorting master block")
        self._build_master_block(ranges)
        self._sort_master_block()

        if self._missing_status_ranges:
            msg = "IPAM data has {} ranges with missing ['customProperties']['Status']\n".format(len(self._missing_status_ranges))
            range_list = "\n".join(ri['name'] for ri in self._missing_status_ranges)
            msg += "\nList of ranges that have this issue: \n{}".format(range_list)
            msg += "\nContact IPAM owner and get this issue fixed."
            logging.warning("%s", msg)

        overlap_list = self.find_overlaps()
        if  overlap_list:
            logging.error("%d overlapping ranges found", len(overlap_list))
            for ol in overlap_list:
                logging.error("Overlap Range Info: %s", ol)

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

#-----------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    import optparse
    usage = "usage: %prog  [-l|--log log_dir]"
    log_dir = r'D:\Logs\IntelIPAM' if os.name == 'nt' else '/tmp'
    parser = optparse.OptionParser(usage)
    parser.add_option('-l', '--log',
        default=log_dir,
        help=f"directory to create logfiles. Default {log_dir}")

    options, args = parser.parse_args()

    logutil.set_logging(log_file=options.log)

    logging.info("Starting IntelIPAM with args: %s", args)

    ipam_dl = IntelIPAMDownloader()
    ipam_dl.update_ranges()

