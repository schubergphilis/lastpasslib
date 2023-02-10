from .datamodels import SharedFolder


class LastpassMock:

    def __init__(self, username, domain='lastpass.com'):
        self.domain = domain
        self.host = f'https://{domain}'
        self.username = username
        self.iteration_count = 100100

    def get_shared_folder_by_id(self, id_):
        params = ['x' for _ in range(16)]
        params.insert(0, id_)
        return SharedFolder(*params)

# Decryption code can be tested in isolation by applying it to downloaded vault blob.
# A vault blob can be saved from a proper authenticated session like:
#
# from lastpass.lastpass import Lastpass
# lastpass = Lastpass(USERNAME, PASSWORD, MFA)
# with open('vault.blob', 'w') as ofile:
#     ofile.write(lastpass.vault._blob.decode('utf-8'))

# and can be loaded to test the decryption code in isolation like:
#
# from lastpasslib.utils import LastpassMock
# from lastpasslib.vault import Vault
#
# lastpass = LastpassMock(CORRECT_USERNAME)
# vault = Vault(lastpass, CORRECT_PASSWORD)
# with open('vault.blob') as ifile:
#     data = ifile.read().encode('utf-8')
#
# secrets = vault._decrypt_blob(data)
