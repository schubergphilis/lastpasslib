import logging
import re
from hashlib import sha256, pbkdf2_hmac

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import number
from binascii import hexlify

from .configuration import ALLOWED_SECURE_NOTE_TYPES
from .datamodels import SecretHistory
from .decryption import Blob, Decoder, Stream

LOGGER_BASENAME = 'entities'
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class Vault:
    def __init__(self, lastpass_instance, password):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self._lastpass = lastpass_instance
        self.username = lastpass_instance.username.encode('utf-8')
        self.password = password.encode('utf-8')
        self.key_iteration_count = lastpass_instance.iteration_count
        self._key = None
        self._hash = None
        self._blob_ = None
        self._secrets = None

    @property
    def key(self):
        if self._key is None:
            if self.key_iteration_count == 1:
                self._key = sha256(f'{self.username}{self.password}').digest()
            else:
                self._key = pbkdf2_hmac('sha256', self.password, self.username, self.key_iteration_count, 32)
        return self._key

    @property
    def hash(self):
        if self._hash is None:
            if self.key_iteration_count == 1:
                self._hash = bytearray(sha256(hexlify(self.key) + self.password).hexdigest(), 'ascii')
            else:
                self._hash = hexlify(pbkdf2_hmac('sha256', self.key, self.password, 1, 32))
        return self._hash

    @property
    def _blob(self):
        if self._blob_ is None:
            params = {'mobile': 1,
                      'b64': 1,
                      'hash': 0.0,
                      'hasplugin': '3.0.23',
                      'requestsrc': 'android'}
            url = f'{self._lastpass.host}/getaccts.php'
            response = self._lastpass.session.get(url, params=params)
            if not response.ok:
                response.raise_for_status()
            self._blob_ = response.content
        return self._blob_

    @property
    def secrets(self):
        if not self._secrets:
            self._secrets = self._decrypt_blob(self._blob)
        return self._secrets

    def _decrypt_blob(self, data):
        blob = Blob(data)
        secrets = []
        key = self.key
        rsa_private_key = None
        shared_folder = None
        for chunk in blob.chunks:
            if chunk.id == b'ACCT':
                secrets.append(self._parse_secret(chunk, key, self._lastpass, shared_folder))
            elif chunk.id == b'PRIK':
                rsa_private_key = self._decrypt_rsa_key(chunk, self.key)
            elif chunk.id == b'SHAR':
                # After SHAR chunk all the following accounts are encrypted with a new key.
                # SHAR chunks hold shared folders so shared folders are passed into all accounts under them.
                folder_id, folder_name, key = self._parse_shared_folder(chunk, self.key, rsa_private_key)
                shared_folder = self._lastpass.get_shared_folder_by_id(folder_id.decode('utf-8'))
                shared_folder.shared_name = folder_name.decode('utf-8')
        return secrets

    @staticmethod
    def _parse_secret(chunk, encryption_key, lastpass_instance, shared_folder):
        """Parses an account chunk, decrypts and creates an Account object.
        All secure notes are ACCTs but not all of them store account information.
        """
        stream = Stream(chunk.payload)
        id_ = stream.next_item()
        name = Decoder.decode_aes256_auto(stream.next_item(), encryption_key)
        group = Decoder.decode_aes256_auto(stream.next_item(), encryption_key)
        url = Decoder.decode_hex(stream.next_item())
        notes = Decoder.decode_aes256_auto(stream.next_item(), encryption_key)
        stream.skip_item(2)
        username = Decoder.decode_aes256_auto(stream.next_item(), encryption_key)
        password = Decoder.decode_aes256_auto(stream.next_item(), encryption_key)
        stream.skip_item(2)
        secure_note = stream.next_item()
        if secure_note == b'1':
            parsed_notes = Vault._parse_secure_note(notes)
            if parsed_notes.get('type') in ALLOWED_SECURE_NOTE_TYPES:
                url = parsed_notes.get('url', url)
                username = parsed_notes.get('username', username)
                password = parsed_notes.get('password', password)
        return Secret(lastpass_instance, id_, name, username, password, url, group, notes, shared_folder)

    @staticmethod
    def _parse_secure_note(notes):
        info = {}
        valid_lines = [line for line in notes.split(b'\n')
                       if not any([not line, b':' not in line])]
        key_mapping = {b'NoteType': 'type',
                       b'Hostname': 'url',
                       b'Username': 'username',
                       b'Password': 'password'}
        for line in valid_lines:
            # Split only once so that strings like "Hostname:host.example.com:80" get interpreted correctly
            key, value = line.split(b':', 1)
            entry = key_mapping.get(key)
            if entry:
                info[entry] = value
        return info

    @staticmethod
    def _decrypt_rsa_key(chunk, encryption_key):
        """Parse PRIK chunk which contains private RSA key"""
        decrypted = Decoder.decode_aes256_cbc(encryption_key[:16],
                                              Decoder.decode_hex(chunk.payload),
                                              encryption_key)
        regex_match = br'^LastPassPrivateKey<(?P<hex_key>.*)>LastPassPrivateKey$'
        hex_key = re.match(regex_match, decrypted).group('hex_key')
        rsa_key = RSA.importKey(Decoder.decode_hex(hex_key))
        rsa_key.dmp1 = rsa_key.d % (rsa_key.p - 1)
        rsa_key.dmq1 = rsa_key.d % (rsa_key.q - 1)
        rsa_key.iqmp = number.inverse(rsa_key.q, rsa_key.p)
        return rsa_key

    @staticmethod
    def _parse_shared_folder(chunk, encryption_key, rsa_key):
        stream = Stream(chunk.payload)
        id_ = stream.next_item()
        encrypted_key = Decoder.decode_hex(stream.next_item())
        encrypted_name = stream.next_item()
        stream.skip_item(2)
        key = stream.next_item()
        # Shared folder encryption key might come already in pre-decrypted form,
        # where it's only AES encrypted with the regular encryption key.
        # When the key is blank, then there's a RSA encrypted key, which has to
        # be decrypted first before use.
        if not key:
            key = Decoder.decode_hex(PKCS1_OAEP.new(rsa_key).decrypt(encrypted_key))
        else:
            key = Decoder.decode_hex(Decoder.decode_aes256_auto(key, encryption_key))
        name = Decoder.decode_aes256_auto(encrypted_name, key, base64=True)
        return id_, name, key

    def refresh(self):
        self._logger.info('Cleaning up secrets and blob.')
        self._secrets = None
        self._blob_ = None
        self._logger.info('Re retrieving secrets.')
        _ = self.secrets


class Secret(object):
    def __init__(self, lastpass_instance, id_, name, username, password, url, group, notes=None, shared_folder=None):
        self._lastpass = lastpass_instance
        self.id = id_.decode('utf-8')
        self.name = name.decode('utf-8')
        self.username = username.decode('utf-8')
        self.password = password.decode('utf-8')
        self.url = url.decode('utf-8')
        self.group = group.decode('utf-8')
        self.notes = notes.decode('utf-8')
        self.shared_folder = shared_folder
        self._history = None

    @property
    def history(self):
        if self._history is None:
            url = f'{self._lastpass.host}/lmiapi/accounts/{self.id}/history/note'
            params = {'sharedFolderId': self.shared_folder.id} if self.shared_folder else {}
            response = self._lastpass.session.get(url, params=params)
            if not response.ok:
                response.raise_for_status()
            self._history = [SecretHistory(*data.values()) for data in response.json().get('history', [])]
        return self._history

    def get_latest_update_person(self):
        try:
            return self.history[-1].person
        except IndexError:
            return None
