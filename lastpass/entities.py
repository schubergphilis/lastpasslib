import logging
from copy import copy
from datetime import datetime
from hashlib import sha256, pbkdf2_hmac
from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify

from .configuration import ALLOWED_SECURE_NOTE_TYPES
from .datamodels import History
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

    def get_secret_by_name(self, name):
        return next((secret for secret in self.secrets if secret.name == name), None)

    def _decrypt_blob(self, data):
        blob = Blob(data)
        secrets = []
        key = self.key
        rsa_private_key = None
        shared_folder = None
        for chunk in blob.chunks:
            if chunk.id == b'ACCT':
                data = self._parse_secret(chunk.payload, key)
                secrets.append(Secret(self._lastpass, data, shared_folder))
            elif chunk.id == b'PRIK':
                rsa_private_key = Decoder.decrypt_rsa_key(chunk.payload, self.key)
            elif chunk.id == b'SHAR':
                # After SHAR chunk all the following accounts are encrypted with a new key.
                # SHAR chunks hold shared folders so shared folders are passed into all accounts under them.
                folder_id, folder_name, key = self._parse_shared_folder(chunk.payload, self.key, rsa_private_key)
                shared_folder = self._lastpass.get_shared_folder_by_id(folder_id.decode('utf-8'))
                shared_folder.shared_name = folder_name.decode('utf-8')
        return secrets

    @staticmethod
    def _parse_secret(payload, encryption_key):
        """Parses an account chunk, decrypts and creates an Account object.
        All secure notes are ACCTs but not all of them store account information.
        """
        stream = Stream(payload)
        attributes = ['id', 'name', 'group', 'url', 'notes', 'favorite', 'shared_from_id', 'username', 'password',
                      'password_protected', 'generated_password', 'is_secure_note', 'last_touch_timestamp',
                      'auto_login', 'never_autofill', 'realm_data', 'fi_id', 'custom_js', 'submit_id', 'captcha_id',
                      'ur_id', 'basic_auth', 'method', 'action', 'group_id', 'deleted', 'attachment_encryption_key',
                      'has_attachment', 'is_individual_share', 'note_type', 'no_alert', 'last_modified_gmt',
                      'has_been_shared', 'last_password_change_gmt', 'created_gmt', 'vulnerable',
                      'auto_change_password_supported', 'breached', 'custom_note_definition_json', 'mfa_seed']
        attributes.extend([f'undocumented_attribute_{index}' for index in range(1, 4)])
        boolean_values = ['favorite', 'password_protected', 'generated_password', 'is_secure_note', 'auto_login',
                          'never_autofill', 'basic_auth', 'deleted', 'has_attachment', 'is_individual_share',
                          'no_alert', 'has_been_shared', 'vulnerable', 'auto_change_password_supported', 'breached',
                          'undocumented_attribute_2', 'undocumented_attribute_3']
        plain_encrypted = ['name', 'group', 'notes', 'username', 'password', 'mfa_seed', 'undocumented_attribute_1']
        data = {attribute: stream.get_payload_by_size(stream.read_byte_size(4)) for attribute in attributes}
        decrypted_data = {attribute: Decoder.decrypt_aes256_auto(data.get(attribute), encryption_key)
                          for attribute in plain_encrypted}
        data.update(decrypted_data)
        data['attachment_encryption_key'] = Decoder.decrypt_aes256_auto(data.get('attachment_encryption_key'),
                                                                        encryption_key,
                                                                        base64=True)
        data['url'] = Decoder.decode_hex(data.get('url'))
        decoded_data = {key: value.decode('utf-8') for key, value in data.items()}
        boolean_data = {attribute: bool(decoded_data.get(attribute)) for attribute in boolean_values}
        decoded_data.update(boolean_data)
        if decoded_data.get('is_secure_note') == '1':
            parsed_notes = Vault._parse_secure_note(decoded_data.get('notes'))
            if parsed_notes.get('type') in ALLOWED_SECURE_NOTE_TYPES:
                decoded_data['url'] = parsed_notes.get('url', decoded_data.get('url'))
                decoded_data['username'] = parsed_notes.get('username', decoded_data.get('username'))
                decoded_data['password'] = parsed_notes.get('password', decoded_data.get('password'))
        return decoded_data

    @staticmethod
    def _parse_secure_note(notes):
        info = {}
        valid_lines = [line for line in notes.split('\n')
                       if not any([not line, ':' not in line])]
        key_mapping = {'NoteType': 'type',
                       'Hostname': 'url',
                       'Username': 'username',
                       'Password': 'password'}
        for line in valid_lines:
            # Split only once so that strings like "Hostname:host.example.com:80" get interpreted correctly
            key, value = line.split(':', 1)
            entry = key_mapping.get(key)
            if entry:
                info[entry] = value
        return info

    @staticmethod
    def _parse_shared_folder(payload, encryption_key, rsa_key):
        stream = Stream(payload)
        id_ = stream.get_payload_by_size(stream.read_byte_size(4))
        encrypted_key = Decoder.decode_hex(stream.get_payload_by_size(stream.read_byte_size(4)))
        encrypted_name = stream.get_payload_by_size(stream.read_byte_size(4))
        unknown_flag_1 = stream.get_payload_by_size(stream.read_byte_size(4))
        unknown_flag_2 = stream.get_payload_by_size(stream.read_byte_size(4))
        key = stream.get_payload_by_size(stream.read_byte_size(4))
        # Shared folder encryption key might come already in pre-decrypted form,
        # where it's only AES encrypted with the regular encryption key.
        # When the key is blank, then there's an RSA encrypted key, which has to
        # be decrypted first before use.
        if not key:
            hex_key = PKCS1_OAEP.new(rsa_key).decrypt(encrypted_key)
        else:
            hex_key = Decoder.decrypt_aes256_auto(key, encryption_key)
        key = Decoder.decode_hex(hex_key)
        name = Decoder.decrypt_aes256_auto(encrypted_name, key, base64=True)
        return id_, name, key

    def refresh(self):
        self._logger.info('Cleaning up secrets and blob.')
        self._secrets = self._blob_ = None
        self._logger.info('Retrieving remote blob and decrypting secrets.')
        _ = self.secrets

    def save(self, path='.', name='vault.blob'):
        with open(Path(path, name), 'w') as ofile:
            ofile.write(self._blob.decode('utf-8'))


class Secret(object):
    def __init__(self, lastpass_instance, data, shared_folder=None):
        self._lastpass = lastpass_instance
        self._data = data
        self._shared_folder = shared_folder
        self._note_history = None
        self._username_history = None
        self._password_history = None

    @property
    def id(self):
        return self._data.get('id')

    @property
    def name(self):
        return self._data.get('name')

    @property
    def username(self):
        return self._data.get('username')

    @property
    def password(self):
        return self._data.get('password')

    @property
    def url(self):
        return self._data.get('url')

    @property
    def notes(self):
        return self._data.get('notes')

    @property
    def shared_folder(self):
        return self._shared_folder

    @property
    def last_touch_datetime(self):
        return datetime.fromtimestamp(int(self._data.get('last_touch_timestamp')))

    @property
    def last_modified_datetime(self):
        return datetime.fromtimestamp(int(self._data.get('last_modified_gmt')))

    @property
    def last_password_change_datetime(self):
        return datetime.fromtimestamp(int(self._data.get('last_password_change_gmt')))

    @property
    def created_datetime(self):
        return datetime.fromtimestamp(int(self._data.get('created_gmt')))

    @property
    def note_history(self):
        if self._note_history is None:
            self._note_history = self._get_history_by_attribute('note')
        return self._note_history

    @property
    def username_history(self):
        if self._username_history is None:
            self._username_history = self._get_history_by_attribute('username')
        return self._username_history

    @property
    def password_history(self):
        if self._password_history is None:
            self._password_history = self._get_history_by_attribute('password')
        return self._password_history

    def _get_history_by_attribute(self, attribute):
        url = f'{self._lastpass.host}/lmiapi/accounts/{self.id}/history/{attribute}'
        params = {'sharedFolderId': self.shared_folder.id} if self.shared_folder else {}
        response = self._lastpass.session.get(url, params=params)
        if not response.ok:
            response.raise_for_status()
        decrypted_entries = []
        for entry in response.json().get('history', []):
            new = copy(entry)
            value = Decoder.decrypt_aes256_auto(entry.get('value').encode('utf-8'),
                                                self._lastpass.vault.key,
                                                base64=True)
            try:
                new['value'] = value.decode('utf-8')
            except UnicodeDecodeError:
                new['value'] = str(value)
            decrypted_entries.append(new)
        return [History(*data.values()) for data in decrypted_entries]

    def get_latest_password_update_person(self):
        try:
            return self.password_history[-1].person
        except IndexError:
            return None
