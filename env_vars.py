import secret_util
su = secret_util.SecretUtil()
IPAM_API_USER = su.get_secret('KEYRING:IPAM:IPAM_API_USER')
IPAM_API_PASSWORD = su.get_secret('KEYRING:IPAM:IPAM_API_PASSWORD')
