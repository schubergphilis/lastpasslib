#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: vault.py
#
# Copyright 2023 Costas Tyfoxylos
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
Main code for vault.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import json
import logging
import re
from hashlib import sha256, pbkdf2_hmac
from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify

from .datamodels import NeverUrl, EquivalentDomain, UrlRule
from .dataschemas import SecretSchema, SharedFolderSchema, AttachmentSchema
from .encryption import Blob, EncryptManager, Stream
from .secrets import Password, SECRET_NOTE_CLASS_MAPPING, Attachment, Custom

LOGGER_BASENAME = 'vault'
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''08-02-2023'''
__copyright__ = '''Copyright 2023, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class Vault:
    """Models the encrypted vault and implements decryption of all items and connection everything appropriately."""

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
        self._attachments_ = None
        self._never_urls = None
        self._equivalent_domains = None
        self._url_rules = None
        self.unable_to_decrypt = []

    @property
    def key(self):
        """The encryption key of the vault."""
        if self._key is None:
            if self.key_iteration_count == 1:
                self._key = sha256(f'{self.username}{self.password}').digest()
            else:
                self._key = pbkdf2_hmac('sha256', self.password, self.username, self.key_iteration_count, 32)
        return self._key

    @property
    def hash(self):
        """The hash of the vault."""
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
        """The decrypted secrets of the vault."""
        if self._secrets is None:
            self._secrets = self._decrypt_blob(self._blob)
        return self._secrets

    @property
    def _attachments(self):
        if self._attachments_ is None:
            # parse blob and get secrets and attachments
            _ = self.secrets
        return self._attachments_

    @property
    def never_urls(self):
        """A list of never urls of the vault."""
        if self._never_urls is None:
            # parse blob to get never urls
            _ = self.secrets
        return self._never_urls

    @property
    def equivalent_domains(self):
        """A list of equivalent of the vault."""
        if self._equivalent_domains is None:
            # parse blob to get equivalent domains
            _ = self.secrets
        return self._equivalent_domains

    @property
    def url_rules(self):
        """A list of url rules of the vault."""
        if self._url_rules is None:
            # parse blob to get url rules
            _ = self.secrets
        return self._url_rules

    def get_secret_by_name(self, name):
        """Gets a secret from the vault by name.

        Args:
            name: The name to match on, case-sensitive.

        Returns:
            The secret if a match is found, else None.

        """
        return next((secret for secret in self.secrets if secret.name == name), None)

    def _get_attachments_by_parent_id(self, id_):
        return [attachment for attachment in self._attachments if attachment.get('parent_id') == id_]

    def _decrypt_blob(self, data):  # pylint: disable=too-many-locals
        blob = Blob(data)
        secrets = []
        key = self.key
        rsa_private_key = None
        shared_folder = None
        attachment_chunks = [chunk for chunk in blob.chunks if chunk.id == b'ATTA']
        self._attachments_ = [self._parse_attachment(chunk.payload) for chunk in attachment_chunks]
        never_urls_chunks = [chunk for chunk in blob.chunks if chunk.id == b'NEVR']
        self._never_urls = [self._parse_never_urls(chunk.payload) for chunk in never_urls_chunks]
        eqdn_chunks = [chunk for chunk in blob.chunks if chunk.id == b'EQDN']
        self._equivalent_domains = [self._parse_eqdns(chunk.payload) for chunk in eqdn_chunks]
        urul_chunks = [chunk for chunk in blob.chunks if chunk.id == b'URUL']
        self._url_rules = [self._parse_url_rules(chunk.payload) for chunk in urul_chunks]
        for chunk in blob.chunks:
            if chunk.id == b'ACCT':
                try:
                    class_type, data = self._parse_secret(chunk.payload, key)
                    secret = class_type(self._lastpass, data, shared_folder)
                    if secret.has_attachment:
                        for attachment_data in self._get_attachments_by_parent_id(secret.id):
                            attachment_data['decryption_key'] = secret.attachment_encryption_key
                            attachment = Attachment(self._lastpass, attachment_data)
                            secret.add_attachment(attachment)
                # We want to skip any possible error so the process completes and we gather the errors so they can be
                # troubleshot
                except Exception:  # noqa
                    self._logger.exception('Unable to decrypt chunk, adding to the error list.')
                    self.unable_to_decrypt.append((chunk, key))
                    continue
                secrets.append(secret)
            elif chunk.id == b'PRIK':
                rsa_private_key = EncryptManager.decrypt_rsa_key(chunk.payload, self.key)
            elif chunk.id == b'SHAR':
                # After SHAR chunk all the following accounts are encrypted with a new key.
                # SHAR chunks hold shared folders so shared folders are passed into all accounts under them.
                data = self._parse_shared_folder(chunk.payload, self.key, rsa_private_key)
                # folder_id, folder_name, key = self._parse_shared_folder(chunk.payload, self.key, rsa_private_key)
                shared_folder = self._lastpass.get_shared_folder_by_id(data.get('id'))
                shared_folder.shared_name = data.get('name')
                key = data.get('key')
        return secrets

    @staticmethod
    def _parse_url_rules(payload):
        stream = Stream(payload)
        attributes = ['url', 'exact_host', 'exact_port', 'case_insensitive']
        data = {attribute: stream.get_payload_by_size(stream.read_byte_size(4)) for attribute in attributes}
        data['url'] = EncryptManager.decode_hex(data['url'])
        decoded_data = {key: value.decode('utf-8') for key, value in data.items()}
        bools = {attribute: bool(int(decoded_data.get(attribute))) for attribute in attributes[1:]}
        decoded_data.update(bools)
        return UrlRule(**decoded_data)

    @staticmethod
    def _parse_eqdns(payload):
        stream = Stream(payload)
        attributes = ['id', 'url']
        data = {attribute: stream.get_payload_by_size(stream.read_byte_size(4)) for attribute in attributes}
        decoded_data = {key: value.decode('utf-8') for key, value in data.items()}
        return EquivalentDomain(int(decoded_data.get('id')),
                                EncryptManager.decode_hex(decoded_data.get('url')).decode('utf-8'))

    @staticmethod
    def _parse_never_urls(payload):
        stream = Stream(payload)
        attributes = ['id', 'url']
        data = {attribute: stream.get_payload_by_size(stream.read_byte_size(4)) for attribute in attributes}
        decoded_data = {key: value.decode('utf-8') for key, value in data.items()}
        return NeverUrl(int(decoded_data.get('id')),
                        EncryptManager.decode_hex(decoded_data.get('url')).decode('utf-8'))

    @staticmethod
    def _parse_attachment(payload):
        stream = Stream(payload)
        attachment = AttachmentSchema()
        data = Vault._get_attribute_payload_data(stream, attachment.attributes)
        data.update(Vault._get_utf_decoded(data, attachment.decoded_attributes))
        return data

    @staticmethod
    def _parse_secret(payload, encryption_key):
        """Parses an account chunk, decrypts and creates an Account object.

        All secure notes are ACCTs but not all of them store account information.
        """
        stream = Stream(payload)
        secret = SecretSchema()
        data = Vault._get_attribute_payload_data(stream, secret.attributes)
        data.update(Vault._get_decrypted_data(data, secret.plain_encrypted, encryption_key))
        data.update(Vault._get_decrypted_data(data, secret.base_64_encrypted, encryption_key, base64=True))
        data.update(Vault._get_hex_decoded(data, secret.hex_decoded))
        data.update(Vault._get_utf_decoded(data, secret.decoded_attributes))
        data.update(Vault._get_boolean_values(data, secret.boolean_values))
        data['encryption_key'] = encryption_key
        class_type, data = Vault._parse_secure_note(data) if data.get('is_secure_note') else (Password, data)
        return class_type, data

    @staticmethod
    def _get_boolean_values(data, attributes):
        boolean_data = {}
        for attribute in attributes:
            value = data.get(attribute)
            try:
                value = bool(int(value))
            except ValueError:
                LOGGER.error(
                    f'Attribute :{attribute} with value: {value} for secret :{data.get("name")} cannot be cast to bool.')
            boolean_data[attribute] = value
        return boolean_data

    @staticmethod
    def _get_hex_decoded(data, attributes):
        # TODO Elaborate error catching in the iteration.
        hex_decoded_data = {}
        for attribute in attributes:
            hex_decoded_data[attribute] = EncryptManager.decode_hex(data.get(attribute))
        return hex_decoded_data

    @staticmethod
    def _get_utf_decoded(data, attributes):
        decoded_data = {}
        for attribute in attributes:
            value = data.get(attribute)
            try:
                value = value.decode('utf-8')
            except UnicodeDecodeError:
                LOGGER.warning(f'Value :{value} of attribute: {attribute} for secret :{data.get("name")}'
                               f' cannot be decoded. ')
            decoded_data[attribute] = value
        return decoded_data

    @staticmethod
    def _get_decrypted_data(data, attributes, encryption_key, base64=False):
        decrypted_data = {}
        for attribute in attributes:
            value = data.get(attribute)
            try:
                value = EncryptManager.decrypt_aes256_auto(value, encryption_key, base64=base64)
            except ValueError:
                LOGGER.warning(f'Attribute: {attribute} with value :{value} from secret :{decrypted_data.get("name")}'
                               f'could not be decrypted, used as is, decoded to utf-8 if possible.')
            decrypted_data[attribute] = value
        return decrypted_data

    @staticmethod
    def _get_attribute_payload_data(stream, attributes):
        # TODO Elaborate error catching in the iteration.
        return {attribute: stream.get_payload_by_size(stream.read_byte_size(4)) for attribute in attributes}

    @staticmethod
    def _get_class_and_key_mapping(data):
        note_type = data.get('note_type') or 'Generic'
        class_type = SECRET_NOTE_CLASS_MAPPING.get(note_type, SECRET_NOTE_CLASS_MAPPING.get('Custom'))
        key_mapping = class_type.attribute_mapping
        if data.get('note_type').startswith('Custom'):
            # this needs work as the attributes are not part of the class.
            data = json.loads(data.get('custom_note_definition_json'))
            attributes = [entry.get('text') for entry in data.get('fields')]
            key_mapping = {attribute: Vault._sanitize_to_attribute(attribute) for attribute in attributes}
        return class_type, key_mapping

    @staticmethod
    def _sanitize_to_attribute(value):
        delimiters = [';', ',', '_', '-', '*', ' ']  # noqa
        regex_pattern = '|'.join(map(re.escape, delimiters))
        value = re.split(regex_pattern, value)
        return '_'.join([part.lower() for part in value])

    @staticmethod
    def _parse_secure_note(data):
        secret_name = data.get('name')
        class_type, key_mapping = Vault._get_class_and_key_mapping(data)
        note_data = {}
        try:
            valid_lines = [line for line in data.get('notes').split('\n')
                           if not any([not line, ':' not in line])]
            for line in valid_lines:
                # Split only once so that strings like "Hostname:host.example.com:80" get interpreted correctly
                key, value = line.split(':', 1)
                entry = key_mapping.get(key)
                if entry:
                    note_data[entry] = value
            data.update(note_data)
            if class_type == Custom:
                data['custom_attribute_mapping'] = key_mapping
        except TypeError:
            LOGGER.exception(f'Could not identify valid lines in the note of secret {secret_name} maybe it is corrupt?')
        return class_type, data

    @staticmethod
    def _parse_shared_folder(payload, encryption_key, rsa_key):
        stream = Stream(payload)
        folder = SharedFolderSchema()
        data = Vault._get_attribute_payload_data(stream, folder.attributes)
        data.update(Vault._get_hex_decoded(data, folder.hex_decoded))
        key = data.get('key')
        # Shared folder encryption key might come already in pre-decrypted form,
        # where it's only AES encrypted with the regular encryption key.
        # When the key is blank, then there's an RSA encrypted key, which has to
        # be decrypted first before use.
        if not key:
            hex_key = PKCS1_OAEP.new(rsa_key).decrypt(data.get('encrypted_key'))
        else:
            hex_key = EncryptManager.decrypt_aes256_auto(key, encryption_key)
        key = EncryptManager.decode_hex(hex_key)
        data['key'] = key
        data['name'] = EncryptManager.decrypt_aes256_auto(data.get('encrypted_name'), key, base64=True).decode('utf-8')
        data.update(Vault._get_utf_decoded(data, folder.decoded_attributes))
        return data

    def refresh(self):
        """Refreshes the vault by cleaning up the encrypted blob and the decrypted secrets and forcing the retrieval."""
        self._logger.info('Cleaning up secrets and blob.')
        self._secrets = self._blob_ = None
        self._logger.info('Retrieving remote blob and decrypting secrets.')
        _ = self.secrets

    def save(self, path='.', name='vault.blob'):
        """Can save the downloaded blob.

        Args:
            path: The path to save the blob to, defaults to local directory.
            name: The name to save the blob as, defaults to "vault.blob".

        Returns:
            None.

        """
        with open(Path(path, name), 'w', encoding='utf8') as ofile:
            ofile.write(self._blob.decode('utf-8'))
