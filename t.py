import io
import requests
import json

data = dict(a=5, b=10)

# ---------------------------------------------------------------------------------------------------------------------
def _get_af_creds():
    '''
    returns (user, password) tuple from keyring. See _IPAM_API_CREDS_KEYSTORE
    documentation on setting the keyring.
    '''
    import env_vars
    return env_vars.AF_IT_BTRM_LOCAL_USER, env_vars.AF_IT_BTRM_LOCAL_PASSWORD

url = 'https://af01p-sc.devtools.intel.com/artifactory/it-btrm-local/intel-ipam/test.gz'

auth = _get_af_creds()
print(f"AUTH: {auth}")

with io.StringIO() as fd:
    json.dump(data, fd)
    fd.seek(0)
    print(f"Data: {fd.read()}")
    fd.seek(0)
    print(f"Upload URL: {url}")
    r = requests.put(url, auth=auth, data=fd)
    print(f"Resp headers: {r.headers}")
    print(f"Req headers: {r.request.headers}")
    print(f"Status: {r.status_code}")
    r.raise_for_status()
    print(f"Resp Content: {r.json()}")

