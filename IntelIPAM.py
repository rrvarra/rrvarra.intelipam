r'''

    Module import: Use IntelIPAM() constructor to create an instance. In this mode, it will load latest
    IPAM Range (zipped json) file from a local temp directory (<TEMP>/IntelIPAM/<*.gz>).
        if the file is older (last modified time > 1day), makes a check for latest file in Artifactory REPO to see if there
        is newer version and updates the TEMP dir cache.

     The object's lookup_ip() provides look up functionality.
    In this mode, IPAM api will not be accessed, hence credential setup is not needed.  The directory where
    the gz files are downloaded should be specified in the constructor of IntelIPAM()

    3) Run the script without any argument: Runs unit tests on lookup_ip().

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
import tempfile
from pathlib import Path
import getpass
import json
import logging
import ipaddress
import time
import gzip
from pprint import pprint, pformat
import requests

# ---------------------------------------------------------------------------------------------------------------------
class IntelIPAM:

    # minimum number of ranges expected from IPAM - for data quality check
    _MINIMUM_RANGES_EXPECTED = 20000

    # Json/zip files should start with this prefix and end with .json or .zip (case sensitive)
    _IPAM_FILE_PREFIX = 'Intel_IPAM_Ranges-'

    # Artifactory location to store/fetch IPAM range zipped json files
    _IPAM_AF_URL = 'https://af01p-sc.devtools.intel.com/artifactory'
    _IPAM_AF_REPO_PATH = 'it-btrm-local/intel-ipam'


    # ---------------------------------------------------------------------------------------------------------------------
    def __init__(self, cache_dir: str=None, init_mb:bool =True, ignore_cache: bool=False):
        '''
        cache_dir: directory where ranges.gz file will cached.
        '''
        self._ipam_file, self._master_block  = None, None
        if init_mb:
            self._ipam_file, self._master_block = self._get_range_file(cache_dir, ignore_cache)

            # ensure the master block is sorted
            self.validate()

    def _get_af_gz_files(self) -> list[str]:
        url = f"{self._IPAM_AF_URL}/api/storage/{self._IPAM_AF_REPO_PATH}"
        with requests.Session() as session:
            session.trust_env = False # disable .netrc
            r = session.get(url)
        r.raise_for_status()
        content = r.json()
        if not (children := content.get('children')):
            return []
        files = list(
            sorted(
                cd['uri'].removeprefix('/') for cd in children
                    if not cd['folder']
                        and cd['uri'].startswith(f"/{self._IPAM_FILE_PREFIX}")
                        and cd['uri'].endswith('.gz')
            )
        )
        return files

    def _get_af_gz_file(self) -> str:
        '''
        Fetch information about an artifact
        returns dict with stat and files/subdirs
        This is call makes single api call to fetch the info vs
        dohq_artifactory which requires 2 calls (one for stat to check if its dir
        another to get children).
        '''
        files = self._get_af_gz_files()
        if not files:
            raise Exception(f"NO files in AF")
        return files[-1]

    def _fetch_af_gz_file(self, af_file: str, cache_dir_path: Path) -> tuple[Path, dict]:
        url = f"{self._IPAM_AF_URL}/{self._IPAM_AF_REPO_PATH}/{af_file}"
        logging.info("Fetching ranges from Artifactry %s", url)
        with requests.Session() as session:
            session.trust_env = False # disable .netrc
            r = session.get(url)
            r.raise_for_status()
            content = r.content
        cache_file = cache_dir_path / af_file
        with cache_file.open('wb') as fd_cache:
            fd_cache.write(content)
        with gzip.open(cache_file, 'rt') as zfd:
            mb = json.load(zfd)

        return cache_file, mb

    def _get_range_file(self, cache_dir: str, ignore_cache: bool=False) -> tuple[str, dict]:
        if cache_dir is None:
            cache_dir = os.path.join(tempfile.gettempdir(), f"IntelIPAM_{getpass.getuser()}")
        cache_dir_path = Path(cache_dir)
        if not cache_dir_path.is_dir():
            os.mkdir(cache_dir_path)
        assert cache_dir_path.is_dir()
        # files will be sorted by chrono order
        gz_files = list(sorted(cache_dir_path.glob(f'{self._IPAM_FILE_PREFIX}*.gz')))
        if not ignore_cache and gz_files:
            # try most recent file
            gz_file = cache_dir_path / gz_files[-1]
            mb = None
            if os.path.getmtime(gz_file) < time.time() - 24*3600:
                # file is too old, need check if Artifactory has more recent file
                af_gz_file = self._get_af_gz_file()
                if af_gz_file != gz_file.name:
                    gz_file, mb = self._fetch_af_gz_file(af_gz_file, cache_dir_path)
                else:
                    # AF does not have a new file, update time to keep usage for another day
                    gz_file.touch()
            if not mb:
                logging.info("Loading from %s", gz_file)
                with gzip.open(gz_file, 'rt') as zfd:
                    mb = json.load(zfd)
        else:
            gz_file, mb = self._fetch_af_gz_file(self._get_af_gz_file(), cache_dir_path)

        # remove other cached files
        for fn in gz_files[:-1]:
            fn_path = cache_dir_path / fn
            logging.info("Removing older file: %s", fn_path)
            fn_path.unlink()

        logging.info("Using cache_file: %s", gz_file)
        return gz_file, mb

    # ---------------------------------------------------------------------------------------------------------------------
    def get_ipam_file(self):
        return self._ipam_file

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
            if not range_size_list:
                continue
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
        #logging.info("FIRST %s LAST %s", first, last)
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
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)

    # do testing
    start_ts = time.time()
    ipam = IntelIPAM()

    logging.info("Time to load: {:.1f} secs".format(time.time() - start_ts))

    for ip in ('10.39.165.77', '198.175.95.61', '10.12.86.10', '10.12.104.67', '10.13.17.12', '143.183.250.10', '198.175.123.40', '172.217.4.132'):
        res = ipam.lookup_ip(ip)
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
        res = ipam.lookup_ip(ipa)
    elapsed = time.time() - start_ts
    rate = 1000*elapsed/len(address_list)
    logging.info(f"Lookup time {elapsed:.1f} secs time per lookup: {rate:.3f} milli-secs")
