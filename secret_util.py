'''
Secret management:
    - Either from keyring or as ENV vars
        ENV:VAR_NAME (looks up os env var VAR_NAME)
        KEYRING:SCOPE:NAME (looks up keyring in name NAME scope SCOPE)
        The delimeter can be overriden with delim kw option (e.g. _ for jinja2)
    On Linux, uses: https://pypi.org/project/keyrings.cryptfile/
'''
import os
import getpass
import sys
import logging
import base64

class SecretUtilError(Exception):
    pass

class SecretUtil:
    def __init__(self):
        self._kr = None

    def keyring_lookup(self, scope, name):
        #print("Looking up: scope '%s' name '%s'" % (scope, name))
        try:
            v = self.keyring.get_password(scope, name)
        except Exception as ex:
            raise SecretUtilError(f"Failed to lookup keyring {scope}:{name}") from  ex
        if not v:
            raise SecretUtilError(f"Failed to lookup keyring {scope}:{name} - password empty. $ python3 secret_util.py {scope} {name}")
        return v

    def get_secret(self, name, delim=':'):
        '''
        name can be of the following formats:
            ENV:VAR_NAME (looks up os env var VAR_NAME)
            KEYRING:SCOPE:NAME (looks up keyring in name NAME scope SCOPE)
        '''
        if delim not in name:
            raise SecretUtilError(f"Secret name must have ENV or KEYRING prefix followed by {delim} - bad value {name}")
        st, sn = name.split(delim, maxsplit=1)
        if st == 'ENV':
            if v := os.getenv(sn):
                return v
            raise ValueError(f"ENV Var {sn} not defined")
        if st == 'KEYRING':
            if delim not in sn:
                raise SecretUtilError(f"Missing scope prefix (followed by {delim}) in keyring name {sn}")
            ks, kn = sn.split(delim, maxsplit=1)
            return self.keyring_lookup(ks, kn)

        raise SecretUtilError(f"Invalid secret scheme {st} in name {name}")

    @property
    def keyring(self):
        if self._kr:
            return self._kr
        if sys.platform == 'linux':
            from keyrings.cryptfile.cryptfile import CryptFileKeyring
            self._kr = CryptFileKeyring()
            self._kr.keyring_key = "iue$3i2AuWz283"
        elif sys.platform == 'win32':
            import keyring
            self._kr = keyring
        return self._kr

    def setup_keyring(self, scope, name):
        while True:
            p1 = getpass.getpass(f"Enter secret for KEYRING:{scope}:{name} :")
            p2 = getpass.getpass(f"Renter secret for KEYRING:{scope}:{name}:")
            if p1 == p2:
                break
            print("ERROR: entered passwords did not match - try again")

        self.keyring.set_password(scope, name, p1)
        print(f"Secret KEYRING:{scope}:{name} configured successfully. Verifying...")
        try:
            p2 = self.keyring_lookup(scope, name)
        except SecretUtilError as ex:
            print(f"ERROR: Failed to read KEYRING:{scope}:{name} - {ex}")
        else:
            if p1 == p2:
                print(f"KEYRING:{scope}:{name} verified successfully")
            else:
                print(f"ERROR: Secret verification failed for KEYRING:{scope}:{name}")

if __name__ == '__main__':
    assert len(sys.argv) in (3, 4), f"Usage: {sys.argv[0]} <scope> <name> [show]"
    su = SecretUtil()
    scope, name = sys.argv[1:3]
    assert ':' not in scope, "Scope must not have :"
    assert ':' not in name, "Name must not have :"
    if len(sys.argv) == 4:
        print(su.keyring_lookup(scope, name))
    else:
        su.setup_keyring(scope, name)
