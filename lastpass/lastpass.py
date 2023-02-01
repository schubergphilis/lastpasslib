import codecs
import hashlib
import re
import struct
from base64 import b64decode
from io import BytesIO
from xml.etree import ElementTree as etree
from xml.etree.ElementTree import ParseError

import binascii
import requests
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import number
from binascii import hexlify
from requests import Session

from lastpassexceptions import (InvalidMfa,
                                InvalidPassword,
                                MfaRequired,
                                ServerError,
                                UnknownUsername,
                                UnexpectedResponse)

# Secure note types that contain account-like information
ALLOWED_SECURE_NOTE_TYPES = [
    b"Server",
    b"Email Account",
    b"Database",
    b"Instant Messenger",
]



class Lastpass:

    def __init__(self, username, password, mfa):
        self.username = username
        self.password = password
        self.mfa = mfa
        self._headers = {'user-agent': 'lastpass-python/2.5.0'}
        self._iteration_count = self._get_iterations_by_email(username)
        self._session = self._get_authenticated_session(username, password, mfa)

    @staticmethod
    def _get_iterations_by_email(email):
        url = 'https://lastpass.com/iterations.php'
        response = requests.post(url, data={'email': email})
        if not response.ok:
            response.raise_for_status()
        return response.json()

    @staticmethod
    def make_key(username, password, key_iteration_count):
        # type: (str, str, int) -> bytes
        username = username.encode('utf-8')
        password = password.encode('utf-8')
        if key_iteration_count == 1:
            return hashlib.sha256(f'{username}{password}').digest()
        return hashlib.pbkdf2_hmac('sha256', password, username, key_iteration_count, 32)

    @staticmethod
    def make_hash(username, password, key_iteration_count):
        # type: (str, str, int) -> bytes
        password_utf = password.encode('utf-8')
        key = Lastpass.make_key(username, password, key_iteration_count)
        if key_iteration_count == 1:
            return bytearray(hashlib.sha256(hexlify(key) + password_utf).hexdigest(), 'ascii')
        return hexlify(hashlib.pbkdf2_hmac('sha256', key, password_utf, 1, 32))

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

    def _get_authenticated_session(self, username, password, mfa=None, client_id=None):
        session = Session()
        body = {'method': 'mobile',
                'web': 1,
                'xml': 1,
                'username': username,
                'hash': Lastpass.make_hash(username, password, self._iteration_count),
                'iterations': self._iteration_count, }
        if mfa:
            body['otp'] = mfa
        if client_id:
            body['imei'] = client_id
        response = requests.post('https://lastpass.com/login.php',
                                 data=body,
                                 headers=self._headers)
        parsed_response = self._validate_response(response)
        if parsed_response.tag == 'ok':
            session.cookies.set('PHPSESSID', parsed_response.attrib.get('sessionid'), domain='lastpass.com')
        return session

    def logout(self):
        url = 'https://lastpass.com/logout.php?mobile=1'
        response = self._session.get(url)
        if not response.ok:
            response.raise_for_status()
        return response.ok

    @property
    def secrets(self):
        url = 'https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=android'
        response = self._session.get(url)
        if not response.ok:
            response.raise_for_status()
        container = SecretsContainer(self, response.content, self._iteration_count, self.username, self.password)
        return container.accounts


class SecretsContainer:
    def __init__(self, lastpass_instance, data, key_iteration_count, username, password):
        self._lastpass = lastpass_instance
        self.username = username
        self.password = password
        self.key_iteration_count = key_iteration_count
        self.accounts = self.parse_accounts(data)

    @staticmethod
    def is_complete(chunks):
        if not chunks:
            return False
        conditions = [chunks[-1].id == b'ENDM',
                      chunks[-1].payload == b'OK']
        return all(conditions)

    @staticmethod
    def read_id(stream):
        """Reads a chunk ID from a stream."""
        return stream.read(4)

    @staticmethod
    def read_uint32(stream):
        """Reads an unsigned 32 bit integer from a stream."""
        return struct.unpack('>I', stream.read(4))[0]

    @staticmethod
    def read_size(stream):
        """Reads a chunk or an item ID."""
        return SecretsContainer.read_uint32(stream)

    @staticmethod
    def read_payload(stream, size):
        """Reads a payload of a given size from a stream."""
        return stream.read(size)

    @staticmethod
    def read_chunk(stream):
        """Reads one chunk from a stream and creates a Chunk object with the data read."""
        # LastPass blob chunk is made up of 4-byte ID,
        # big endian 4-byte size and payload of that size.
        #
        # Example:
        #   0000: "IDID"
        #   0004: 4
        #   0008: 0xDE 0xAD 0xBE 0xEF
        #   000C: --- Next chunk ---
        return Chunk(SecretsContainer.read_id(stream), SecretsContainer.read_payload(stream, SecretsContainer.read_size(stream)))

    @staticmethod
    def chunk_data(data):
        chunks = SecretsContainer.extract_chunks(data)
        if not SecretsContainer.is_complete(chunks):
            raise ServerError('Blob is truncated')
        return chunks
    @staticmethod
    def extract_chunks(blob):
        """Splits the blob into chucks grouped by kind."""
        chunks = []
        stream = BytesIO(blob)
        current_pos = stream.tell()
        stream.seek(0, 2)
        length = stream.tell()
        stream.seek(current_pos, 0)
        while stream.tell() < length:
            chunks.append(SecretsContainer.read_chunk(stream))
        return chunks

    def parse_accounts(self, data):
        data = b64decode(data)
        chunks = self.chunk_data(data)
        accounts = []
        encryption_key = Lastpass.make_key(self.username, self.password, self.key_iteration_count)
        key = encryption_key
        rsa_private_key = None
        for i in chunks:
            if i.id == b'ACCT':
                # TODO: Put shared folder name as group in the account
                account = parse_ACCT(i, key, self._lastpass)
                if account:
                    accounts.append(account)
            elif i.id == b'PRIK':
                rsa_private_key = parse_PRIK(i, encryption_key)
            elif i.id == b'SHAR':
                # After SHAR chunk all the folliwing accounts are enrypted with a new key
                key = parse_SHAR(i, encryption_key, rsa_private_key)['encryption_key']

        return accounts


class Account(object):
    def __init__(self, lastpass_instance, id, name, username, password, url, group, notes=None):
        self._lastpass = lastpass_instance
        self.id = id.decode('utf-8')
        self.name = name.decode('utf-8')
        self.username = username.decode('utf-8')
        self.password = password.decode('utf-8')
        self.url = url.decode('utf-8')
        self.group = group.decode('utf-8')
        self.notes = notes.decode('utf-8')

    @property
    def history(self):
        url = f'https://lastpass.com/lmiapi/accounts/{self.id}/history/note'
        response = self._lastpass._session.get(url)
        if not response.ok:
            response.raise_for_status()
        return response.json().get('history')



class Chunk(object):
    def __init__(self, id, payload):
        self.id = id
        self.payload = payload

    def __eq__(self, other):
        return self.id == other.id and self.payload == other.payload


def parse_ACCT(chunk, encryption_key, lastpass_instance):
    """
    Parses an account chunk, decrypts and creates an Account object.
    May return nil when the chunk does not represent an account.
    All secure notes are ACCTs but not all of them strore account
    information.
    """
    # TODO: Make a test case that covers secure note account

    io = BytesIO(chunk.payload)
    id = read_item(io)
    name = decode_aes256_plain_auto(read_item(io), encryption_key)
    group = decode_aes256_plain_auto(read_item(io), encryption_key)
    url = decode_hex(read_item(io))
    notes = decode_aes256_plain_auto(read_item(io), encryption_key)
    skip_item(io, 2)
    username = decode_aes256_plain_auto(read_item(io), encryption_key)
    password = decode_aes256_plain_auto(read_item(io), encryption_key)
    skip_item(io, 2)
    secure_note = read_item(io)

    # Parse secure note
    if secure_note == b'1':
        parsed = parse_secure_note_server(notes)

        if parsed.get('type') in ALLOWED_SECURE_NOTE_TYPES:
            url = parsed.get('url', url)
            username = parsed.get('username', username)
            password = parsed.get('password', password)

    return Account(lastpass_instance, id, name, username, password, url, group, notes)


def parse_PRIK(chunk, encryption_key):
    """Parse PRIK chunk which contains private RSA key"""
    decrypted = decode_aes256('cbc',
                              encryption_key[:16],
                              decode_hex(chunk.payload),
                              encryption_key)

    hex_key = re.match(br'^LastPassPrivateKey<(?P<hex_key>.*)>LastPassPrivateKey$', decrypted).group('hex_key')
    rsa_key = RSA.importKey(decode_hex(hex_key))

    rsa_key.dmp1 = rsa_key.d % (rsa_key.p - 1)
    rsa_key.dmq1 = rsa_key.d % (rsa_key.q - 1)
    rsa_key.iqmp = number.inverse(rsa_key.q, rsa_key.p)

    return rsa_key


def parse_SHAR(chunk, encryption_key, rsa_key):
    # TODO: Fake some data and make a test
    io = BytesIO(chunk.payload)
    id = read_item(io)
    encrypted_key = decode_hex(read_item(io))
    encrypted_name = read_item(io)
    skip_item(io, 2)
    key = read_item(io)

    # Shared folder encryption key might come already in pre-decrypted form,
    # where it's only AES encrypted with the regular encryption key.
    # When the key is blank, then there's a RSA encrypted key, which has to
    # be decrypted first before use.
    if not key:
        key = decode_hex(PKCS1_OAEP.new(rsa_key).decrypt(encrypted_key))
    else:
        key = decode_hex(decode_aes256_plain_auto(key, encryption_key))
    name = decode_aes256_base64_auto(encrypted_name, key)

    # TODO: Return an object, not a dict
    return {'id': id, 'name': name, 'encryption_key': key}


def parse_secure_note_server(notes):
    info = {}

    for i in notes.split(b'\n'):
        if not i:  # blank line
            continue

        if b':' not in i:  # there is no `:` if generic note
            continue

        # Split only once so that strings like "Hostname:host.example.com:80"
        # get interpreted correctly
        key, value = i.split(b':', 1)
        if key == b'NoteType':
            info['type'] = value
        elif key == b'Hostname':
            info['url'] = value
        elif key == b'Username':
            info['username'] = value
        elif key == b'Password':
            info['password'] = value

    return info


def read_item(stream):
    """Reads an item from a stream and returns it as a string of bytes."""
    # An item in an itemized chunk is made up of the
    # big endian size and the payload of that size.
    #
    # Example:
    #   0000: 4
    #   0004: 0xDE 0xAD 0xBE 0xEF
    #   0008: --- Next item ---
    return SecretsContainer.read_payload(stream, SecretsContainer.read_size(stream))


def skip_item(stream, times=1):
    """Skips an item in a stream."""
    for i in range(times):
        read_item(stream)


def decode_hex(data):
    """Decodes a hex encoded string into raw bytes."""
    try:
        return codecs.decode(data, 'hex_codec')
    except binascii.Error:
        raise TypeError()


def decode_base64(data):
    """Decodes a base64 encoded string into raw bytes."""
    return b64decode(data)


def decode_aes256_plain_auto(data, encryption_key):
    """Guesses AES cipher (EBC or CBD) from the length of the plain data."""
    assert isinstance(data, bytes)
    length = len(data)

    if length == 0:
        return b''
    elif data[0] == b'!'[0] and length % 16 == 1 and length > 32:
        return decode_aes256_cbc_plain(data, encryption_key)
    else:
        return decode_aes256_ecb_plain(data, encryption_key)


def decode_aes256_base64_auto(data, encryption_key):
    """Guesses AES cipher (EBC or CBD) from the length of the base64 encoded data."""
    assert isinstance(data, bytes)
    length = len(data)

    if length == 0:
        return b''
    elif data[0] == b'!'[0]:
        return decode_aes256_cbc_base64(data, encryption_key)
    else:
        return decode_aes256_ecb_base64(data, encryption_key)


def decode_aes256_ecb_plain(data, encryption_key):
    """Decrypts AES-256 ECB bytes."""
    if not data:
        return b''
    else:
        return decode_aes256('ecb', '', data, encryption_key)


def decode_aes256_ecb_base64(data, encryption_key):
    """Decrypts base64 encoded AES-256 ECB bytes."""
    return decode_aes256_ecb_plain(decode_base64(data), encryption_key)


def decode_aes256_cbc_plain(data, encryption_key):
    """Decrypts AES-256 CBC bytes."""
    if not data:
        return b''
    else:
        # LastPass AES-256/CBC encryted string starts with an "!".
        # Next 16 bytes are the IV for the cipher.
        # And the rest is the encrypted payload.
        return decode_aes256('cbc', data[1:17], data[17:], encryption_key)


def decode_aes256_cbc_base64(data, encryption_key):
    """Decrypts base64 encoded AES-256 CBC bytes."""
    if not data:
        return b''
    else:
        # LastPass AES-256/CBC/base64 encryted string starts with an "!".
        # Next 24 bytes are the base64 encoded IV for the cipher.
        # Then comes the "|".
        # And the rest is the base64 encoded encrypted payload.
        return decode_aes256(
            'cbc',
            decode_base64(data[1:25]),
            decode_base64(data[26:]),
            encryption_key)


def decode_aes256(cipher, iv, data, encryption_key):
    """
    Decrypt AES-256 bytes.
    Allowed ciphers are: :ecb, :cbc.
    If for :ecb iv is not used and should be set to "".
    """
    if cipher == 'cbc':
        aes = AES.new(encryption_key, AES.MODE_CBC, iv)
    elif cipher == 'ecb':
        aes = AES.new(encryption_key, AES.MODE_ECB)
    else:
        raise ValueError('Unknown AES mode')
    d = aes.decrypt(data)
    # http://passingcuriosity.com/2009/aes-encryption-in-python-with-m2crypto/
    unpad = lambda s: s[0:-ord(d[-1:])]
    return unpad(d)
