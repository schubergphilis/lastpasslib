import datetime
import re
from hashlib import sha256, pbkdf2_hmac
from xml.etree import ElementTree as etree
from xml.etree.ElementTree import ParseError
from dateutil.parser import parse

import requests
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import number
from binascii import hexlify
from requests import Session

from .entities import (AccountHistory,
                       Blob,
                       Decoder,
                       Secret,
                       SharedFolder,
                       Stream)
from .lastpassexceptions import (InvalidMfa,
                                 InvalidPassword,
                                 MfaRequired,
                                 ServerError,
                                 UnknownUsername,
                                 UnexpectedResponse)

# Secure note types that contain account-like information
ALLOWED_SECURE_NOTE_TYPES = [
    b"Server",
    b"Email Account",
    b"SSH Key",
    b"Database",
    b"Stripe Key",
    b"Passport",
    b"Membership",
    b"Wi-Fi Password",
    b"Software License",
    b"Social Security",
    b"Address",
    b"Bank Account",
    b"Credit Card",
    b"Email Account",
    b"Health Insurance",
    b"Insurance",
    b"Instant Messenger",
    b"Generic",
    b"Custom",
]


class Lastpass:

    def __init__(self, username, password, mfa, domain='lastpass.com'):
        self.domain = domain
        self.host = f'https://{domain}'
        self.username = username
        self._iteration_count = None
        self._vault = Vault(self, password)
        self._authenticated_response_data = None
        self._session = self._get_authenticated_session(username, mfa)
        self._shared_folders = None

    @property
    def iteration_count(self):
        if self._iteration_count is None:
            url = f'{self.host}/iterations.php'
            response = requests.post(url, data={'email': self.username})
            if not response.ok:
                response.raise_for_status()
            self._iteration_count = response.json()
        return self._iteration_count

    @staticmethod
    def _validate_response(response):
        if not response.ok:
            response.raise_for_status()
        try:
            parsed_response = etree.fromstring(response.content)
        except ParseError:
            raise UnexpectedResponse(response.text)
        error = parsed_response.find('error')
        if error is not None:
            exceptions = {
                'user_not_exists': UnknownUsername,
                'password_invalid': InvalidPassword,
                'googleauthrequired': MfaRequired,
                'microsoftauthrequired': MfaRequired,
                'googleauthfailed': InvalidMfa,
                'microminiaturized': InvalidMfa,
                'restrictiveness': InvalidMfa,
            }
            exception = exceptions.get(error.attrib.get('cause'), ServerError)
            raise exception(error.attrib.get('message'))
        return parsed_response

    def _get_authenticated_session(self, username, mfa=None, client_id=None):
        session = Session()
        body = {'method': 'mobile',
                'web': 1,
                'xml': 1,
                'username': username,
                'hash': self._vault.hash,
                'iterations': self.iteration_count, }
        if mfa:
            body['otp'] = mfa
        if client_id:
            body['imei'] = client_id
        headers = {'user-agent': 'lastpasslib'}
        response = requests.post(f'{self.host}/login.php', data=body, headers=headers)
        parsed_response = self._validate_response(response)
        if parsed_response.tag == 'ok':
            data = parsed_response.attrib
            session.cookies.set('PHPSESSID', data.get('sessionid'), domain=self.domain)
            self._authenticated_response_data = data
        return session

    def logout(self):
        params = {'skip_prompt': 1,
                  'from_uri': '/'}
        url = f'{self.host}/logout'
        response = self._session.get(url, params=params)
        if not response.ok:
            response.raise_for_status()
        return response.ok

    @property
    def shared_folders(self):
        if self._shared_folders is None:
            url = f'{self.host}/getSharedFolderInfo.php'
            data = {'lpversion': '4.0',
                    'method': 'web',
                    'token': self._authenticated_response_data.get('token')}
            response = self._session.post(url, data=data)
            if not response.ok:
                response.raise_for_status()
            self._shared_folders = [SharedFolder(*data.values()) for data in response.json().get('folders')]
            # response.json().get('superusers') exposes a {uid: , key:} dictionary of superusers.
        return self._shared_folders

    def get_shared_folder_by_id(self, id_):
        return next((folder for folder in self.shared_folders if folder.id == id_), None)

    @property
    def vault(self):
        return self._vault

    def get_login_history_by_date(self, start_date=None, end_date=None):
        return self._get_history_by_date(start_date, end_date, 'logins')

    def get_event_history_by_date(self, start_date=None, end_date=None):
        return self._get_history_by_date(start_date, end_date, 'events')

    def _get_history_by_date(self, start_date, end_date, event_type):
        today = datetime.date.today().strftime('%Y-%m-%d')
        start_date = parse(start_date).strftime('%Y-%m-%d') if start_date else today
        end_date = parse(end_date).strftime('%Y-%m-%d') if end_date else today
        form_data = {'start': 0,
                     'limit': 20000,
                     'sort': 'date',
                     'dir': 'ASC'}
        params = {'data': 1,
                  'frame': 1,
                  'aid': None,
                  'startdate': start_date,
                  'enddate': end_date,
                  'type': event_type,
                  'token': self._authenticated_response_data.get('token')}
        url = f'{self.host}/history.php'
        response = self._session.post(url, params=params, data=form_data)
        if not response.ok:
            response.raise_for_status()
        items = response.json().get('response', {}).get('value', {}).get('items', [])
        return [AccountHistory(**item) for item in items]


class Vault:
    def __init__(self, lastpass_instance, password):
        self._lastpass = lastpass_instance
        self.username = lastpass_instance.username.encode('utf-8')
        self.password = password.encode('utf-8')
        self.key_iteration_count = lastpass_instance.iteration_count
        self._key = None
        self._hash = None
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
        params = {'mobile': 1,
                  'b64': 1,
                  'hash': 0.0,
                  'hasplugin': '3.0.23',
                  'requestsrc': 'android'}
        url = f'{self._lastpass.host}/getaccts.php'
        response = self._lastpass._session.get(url, params=params)
        if not response.ok:
            response.raise_for_status()
        return response.content

    @property
    def secrets(self):
        if not self._secrets:
            self._secrets = self._decrypt_blob(self._blob)
        return self._secrets

    def _decrypt_blob(self, data):
        blob = Blob(data)
        accounts = []
        key = encryption_key = self.key
        rsa_private_key = None
        shared_folder = None
        for chunk in blob.chunks:
            if chunk.id == b'ACCT':
                accounts.append(self._parse_secret(chunk, key, self._lastpass, shared_folder))
            elif chunk.id == b'PRIK':
                rsa_private_key = self._decrypt_rsa_key(chunk, encryption_key)
            elif chunk.id == b'SHAR':
                # After SHAR chunk all the following accounts are encrypted with a new key.
                # SHAR chunks hold shared folders so shared folders are passed into all accounts under them.
                folder_id, folder_name, key = self._parse_shared_folder(chunk, encryption_key, rsa_private_key)
                shared_folder = self._lastpass.get_shared_folder_by_id(folder_id.decode('utf-8'))
                shared_folder.shared_name = folder_name.decode('utf-8')
        return accounts

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
