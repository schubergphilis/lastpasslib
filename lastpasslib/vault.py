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
                class_type, data = self._parse_secret(chunk.payload, key)
                secret = class_type(self._lastpass, data, shared_folder)
                if secret.has_attachment:
                    for attachment_data in self._get_attachments_by_parent_id(secret.id):
                        attachment_data['decryption_key'] = secret.attachment_encryption_key
                        attachment = Attachment(self._lastpass, attachment_data)
                        secret.add_attachment(attachment)
                secrets.append(secret)
            elif chunk.id == b'PRIK':
                rsa_private_key = EncryptManager.decrypt_rsa_key(chunk.payload, self.key)
            elif chunk.id == b'SHAR':
                # After SHAR chunk all the following accounts are encrypted with a new key.
                # SHAR chunks hold shared folders so shared folders are passed into all accounts under them.
                folder_id, folder_name, key = self._parse_shared_folder(chunk.payload, self.key, rsa_private_key)
                shared_folder = self._lastpass.get_shared_folder_by_id(folder_id.decode('utf-8'))
                shared_folder.shared_name = folder_name.decode('utf-8')
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
        attributes = ['id', 'parent_id', 'filetype', 'uuid', 'size', 'encrypted_filename']
        data = {attribute: stream.get_payload_by_size(stream.read_byte_size(4)) for attribute in attributes}
        decoded_data = {key: value.decode('utf-8') for key, value in data.items()}
        return decoded_data

    @staticmethod
    def _parse_secret(payload, encryption_key):
        """Parses an account chunk, decrypts and creates an Account object.

        All secure notes are ACCTs but not all of them store account information.
        """
        stream = Stream(payload)
        attributes = ['id', 'name', 'group', 'url', 'notes', 'is_favorite', 'shared_from_id', 'username', 'password',
                      'is_password_protected', 'is_generated_password', 'is_secure_note', 'last_touch_timestamp',
                      'auto_login_set', 'never_autofill', 'realm_data', 'fi_id', 'custom_js', 'submit_id', 'captcha_id',
                      'ur_id', 'is_basic_auth', 'method', 'action', 'group_id', 'is_deleted',
                      'attachment_encryption_key', 'has_attachment', 'is_individual_share', 'note_type', 'no_alert',
                      'last_modified_gmt', 'has_been_shared', 'last_password_change_gmt', 'created_gmt', 'vulnerable',
                      'auto_change_password_supported', 'is_breached', 'custom_note_definition_json', 'mfa_seed']
        attributes.extend([f'undocumented_attribute_{index}' for index in range(1, 4)])
        boolean_values = ['is_favorite', 'is_password_protected', 'is_generated_password', 'is_secure_note',
                          'auto_login_set', 'never_autofill', 'is_basic_auth', 'is_deleted', 'is_individual_share',
                          'has_been_shared', 'auto_change_password_supported', 'is_breached']
        plain_encrypted = ['name', 'group', 'notes', 'username', 'password', 'mfa_seed', 'undocumented_attribute_1']
        data = {attribute: stream.get_payload_by_size(stream.read_byte_size(4)) for attribute in attributes}
        decrypted_data = {attribute: EncryptManager.decrypt_aes256_auto(data.get(attribute), encryption_key)
                          for attribute in plain_encrypted}
        data.update(decrypted_data)
        data['attachment_encryption_key'] = EncryptManager.decrypt_aes256_auto(data.get('attachment_encryption_key'),
                                                                               encryption_key,
                                                                               base64=True)
        data['url'] = EncryptManager.decode_hex(data.get('url'))
        decoded_data = {key: value.decode('utf-8') for key, value in data.items()}
        boolean_data = {attribute: bool(int(decoded_data.get(attribute))) for attribute in boolean_values}
        decoded_data.update(boolean_data)
        is_secure_note = decoded_data.get('is_secure_note')
        decoded_data['encryption_key'] = encryption_key
        class_type, data = Vault._parse_secure_note(decoded_data) if is_secure_note else (Password, decoded_data)
        return class_type, data

    @staticmethod
    def _try_to_identify_note_type_in_notes(notes):
        note_type = notes.splitlines()[0].split(':', 1)[1]
        if note_type not in SECRET_NOTE_CLASS_MAPPING:
            LOGGER.warning('Unknown note type.')
            note_type = 'Custom'
            # raise TypeError(f'Unknown note type :{note_type}')
        return note_type

    @staticmethod
    def _get_class_and_key_mapping(data):
        custom_note_type = SECRET_NOTE_CLASS_MAPPING.get('Custom')
        note_type = data.get('note_type')
        if not note_type:
            note_type = Vault._try_to_identify_note_type_in_notes(data.get('notes'))
            data['note_type'] = note_type
        class_type = SECRET_NOTE_CLASS_MAPPING.get(note_type, custom_note_type)
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
        class_type, key_mapping = Vault._get_class_and_key_mapping(data)
        note_data = {}
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
        return class_type, data

    @staticmethod
    def _parse_shared_folder(payload, encryption_key, rsa_key):
        stream = Stream(payload)
        id_ = stream.get_payload_by_size(stream.read_byte_size(4))
        encrypted_key = EncryptManager.decode_hex(stream.get_payload_by_size(stream.read_byte_size(4)))
        encrypted_name = stream.get_payload_by_size(stream.read_byte_size(4))
        unknown_flag_1 = stream.get_payload_by_size(stream.read_byte_size(4))
        unknown_flag_2 = stream.get_payload_by_size(stream.read_byte_size(4))
        _, _ = unknown_flag_1, unknown_flag_2
        key = stream.get_payload_by_size(stream.read_byte_size(4))
        # Shared folder encryption key might come already in pre-decrypted form,
        # where it's only AES encrypted with the regular encryption key.
        # When the key is blank, then there's an RSA encrypted key, which has to
        # be decrypted first before use.
        if not key:
            hex_key = PKCS1_OAEP.new(rsa_key).decrypt(encrypted_key)
        else:
            hex_key = EncryptManager.decrypt_aes256_auto(key, encryption_key)
        key = EncryptManager.decode_hex(hex_key)
        name = EncryptManager.decrypt_aes256_auto(encrypted_name, key, base64=True)
        return id_, name, key

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
