import secret_util
su = secret_util.SecretUtil()
IPAM_API_USER = su.get_secret('KEYRING:IPAM:IPAM_API_USER')
IPAM_API_PASSWORD = su.get_secret('KEYRING:IPAM:IPAM_API_PASSWORD')
AF_IT_BTRM_LOCAL_USER = su.get_secret('KEYRING:IPAM:AF_IT_BTRM_LOCAL_USER')
AF_IT_BTRM_LOCAL_PASSWORD = su.get_secret('KEYRING:IPAM:AF_IT_BTRM_LOCAL_USER')
