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

from collections import defaultdict
from dataclasses import dataclass
import json
import logging
import re
import time
from hashlib import sha256, pbkdf2_hmac
from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify

from .datamodels import Folder, FolderMetadata, NeverUrl, EquivalentDomain, SharedFolder, UrlRule
from .dataschemas import SecretSchema, SharedFolderSchema, AttachmentSchema
from .encryption import Blob, EncryptManager, Stream
from .secrets import Password, SECRET_NOTE_CLASS_MAPPING, Attachment, Custom, FolderEntry

LOGGER_BASENAME = 'vault'
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''08-02-2023'''
__copyright__ = '''Copyright 2023, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos", "Yorick Hoorneman"]
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
        self._blob = None
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
    def blob(self):
        if self._blob is None:
            params = {'mobile': 1,
                      'b64': 1,
                      'hash': 0.0,
                      'hasplugin': '3.0.23',
                      'requestsrc': 'android'}
            url = f'{self._lastpass.host}/getaccts.php'
            response = self._lastpass.session.get(url, params=params)
            if not response.ok:
                response.raise_for_status()
            self._blob = response.content
        return self._blob

    @staticmethod
    def _get_attachments_by_parent_id(id_, attachments):
        return [attachment for attachment in attachments if attachment.get('parent_id') == id_]

    @staticmethod
    def _get_chunks_by_id(blob, chunk_id):
        return [chunk for chunk in blob.chunks if chunk.id == chunk_id.encode('utf-8')]

    @staticmethod
    def _get_chunk_by_id(blob, chunk_id):
        return next((chunk for chunk in blob.chunks if chunk.id == chunk_id.encode('utf-8')), None)

    def decrypt_blob(self, data):
        blob = Blob(data)
        encrypted_username = Vault._get_chunk_by_id(blob, 'ENCU').payload.decode('utf-8')
        attachments_data = self._get_attachments(blob)
        never_urls = self._get_never_urls(blob)
        equivalent_domains = self._get_eqdns(blob)
        url_rules = self._get_url_rules(blob)
        secrets, attachments, \
            folder_entries, shared_folders = self._get_secrets_folders_and_attachments(blob, attachments_data)
        encryption_key = self.key
        return DecryptedVault(self._lastpass,
                              encrypted_username,
                              attachments,
                              never_urls,
                              equivalent_domains,
                              url_rules, secrets,
                              encryption_key,
                              folder_entries,
                              shared_folders)

    @staticmethod
    def _get_attribute_payload_data(stream, attributes):
        return {attribute: stream.get_payload_by_size(stream.read_byte_size(4)) for attribute in attributes}

    @staticmethod
    def _parse_secret_type(payload, encryption_key):
        """Parses an account chunk, decrypts and creates an Account object.

        All secure notes are ACCTs but not all of them store account information.
        """
        stream = Stream(payload)
        secret = SecretSchema()
        data = Vault._get_attribute_payload_data(stream, secret.attributes)
        data.update(Vault._transform_data_attributes(data,
                                                     secret.plain_encrypted,
                                                     EncryptManager.decrypt_aes256_auto,
                                                     arguments={'encryption_key': encryption_key}))
        data.update(Vault._transform_data_attributes(data,
                                                     secret.base_64_encrypted,
                                                     EncryptManager.decrypt_aes256_auto,
                                                     arguments={'encryption_key': encryption_key,
                                                                'base64': True}))
        data.update(Vault._transform_data_attributes(data,
                                                     secret.hex_decoded,
                                                     EncryptManager.decode_hex))
        data.update(Vault._transform_data_attributes(data,
                                                     secret.decoded_attributes,
                                                     lambda x: x.decode('utf-8')))
        data.update(Vault._transform_data_attributes(data,
                                                     secret.boolean_values,
                                                     lambda x: bool(int(x))))
        data['encryption_key'] = encryption_key
        if data.get('is_secure_note'):
            return Vault._parse_secure_note(data)
        if all([not any([data.get('username'),
                         data.get('password'),
                         data.get('name'),
                         data.get('notes')]),
                data.get('url') == 'http://group']):
            return FolderEntry, data
        return Password, data

    def _parse_secret(self,  # pylint: disable=too-many-arguments
                      chunk,
                      key,
                      shared_folder,
                      attachments_data,
                      attachments,
                      secrets,
                      folder_entries):
        class_type, data = self._parse_secret_type(chunk.payload, key)
        secret = class_type(self._lastpass, data, shared_folder)
        if class_type is FolderEntry:
            folder_entries.append(secret)
        else:
            if secret.has_attachment:
                for attachment_data in self._get_attachments_by_parent_id(secret.id, attachments_data):
                    attachment_data['decryption_key'] = secret.attachment_encryption_key
                    attachment = Attachment(self._lastpass, attachment_data)
                    secret.add_attachment(attachment)
                    attachments.append(attachment)
            secrets.append(secret)
        return secrets, attachments, folder_entries

    def _get_secrets_folders_and_attachments(self, blob, attachments_data):
        secrets = []
        attachments = []
        folder_entries = []
        shared_folders = []
        key = self.key
        rsa_private_key = None
        shared_folder = None
        for chunk in blob.chunks:
            if chunk.id == b'ACCT':
                try:
                    secrets, attachments, folder_entries = self._parse_secret(chunk,
                                                                              key,
                                                                              shared_folder,
                                                                              attachments_data,
                                                                              attachments,
                                                                              secrets,
                                                                              folder_entries)
                # We want to skip any possible error so the process completes and we gather the errors so they can be
                # troubleshoot
                except Exception:  # noqa
                    self._logger.exception('Unable to decrypt chunk, adding to the error list.')
                    self.unable_to_decrypt.append((chunk, key))
                    continue
            elif chunk.id == b'PRIK':
                rsa_private_key = EncryptManager.decrypt_rsa_key(chunk.payload, self.key)
            elif chunk.id == b'SHAR':
                # After SHAR chunk all the following accounts are encrypted with a new key.
                # SHAR chunks hold shared folders so shared folders are passed into all accounts under them.
                data = self._parse_shared_folder(chunk.payload, self.key, rsa_private_key)
                shared_folder_data = self._lastpass._get_shared_folder_data_by_id(data.get('id'))  # pylint: disable=protected-access
                if shared_folder_data:
                    shared_folder_data['shared_name'] = data.get('name')
                    shared_folder = SharedFolder(*shared_folder_data.values())
                    shared_folders.append(shared_folder)
                key = data.get('key')
        return secrets, attachments, folder_entries, shared_folders

    @staticmethod
    def _parse_url_rules(payload):
        stream = Stream(payload)
        attributes = ['url', 'exact_host', 'exact_port', 'case_insensitive']
        data = Vault._get_attribute_payload_data(stream, attributes)
        data['url'] = EncryptManager.decode_hex(data['url'])
        data.update(Vault._transform_data_attributes(data,
                                                     attributes,
                                                     lambda x: x.decode('utf-8')))
        bools = attributes[1:]
        data.update(Vault._transform_data_attributes(data,
                                                     bools,
                                                     lambda x: bool(int(x))))
        return UrlRule(**data)

    @staticmethod
    def _get_url_rules(blob):
        urul_chunks = Vault._get_chunks_by_id(blob, 'URUL')
        return [Vault._parse_url_rules(chunk.payload) for chunk in urul_chunks]

    @staticmethod
    def _parse_eqdns(payload):
        stream = Stream(payload)
        attributes = ['id', 'url']
        data = Vault._get_attribute_payload_data(stream, attributes)
        data.update(Vault._transform_data_attributes(data,
                                                     attributes,
                                                     lambda x: x.decode('utf-8')))
        return EquivalentDomain(int(data.get('id')),
                                EncryptManager.decode_hex(data.get('url')).decode('utf-8'))

    @staticmethod
    def _get_eqdns(blob):
        eqdn_chunks = Vault._get_chunks_by_id(blob, 'EQDN')
        return [Vault._parse_eqdns(chunk.payload) for chunk in eqdn_chunks]

    @staticmethod
    def _parse_never_urls(payload):
        stream = Stream(payload)
        attributes = ['id', 'url']
        data = Vault._get_attribute_payload_data(stream, attributes)
        data.update(Vault._transform_data_attributes(data,
                                                     attributes,
                                                     lambda x: x.decode('utf-8')))
        return NeverUrl(int(data.get('id')),
                        EncryptManager.decode_hex(data.get('url')).decode('utf-8'))

    @staticmethod
    def _get_never_urls(blob):
        never_urls_chunks = Vault._get_chunks_by_id(blob, 'NEVR')
        return [Vault._parse_never_urls(chunk.payload) for chunk in never_urls_chunks]

    @staticmethod
    def _parse_attachment(payload):
        stream = Stream(payload)
        attachment = AttachmentSchema()
        data = Vault._get_attribute_payload_data(stream, attachment.attributes)
        data.update(Vault._transform_data_attributes(data,
                                                     attachment.decoded_attributes,
                                                     lambda x: x.decode('utf-8')))
        return data

    @staticmethod
    def _get_attachments(blob):
        attachment_chunks = Vault._get_chunks_by_id(blob, 'ATTA')
        return [Vault._parse_attachment(chunk.payload) for chunk in attachment_chunks]

    @staticmethod
    def _transform_data_attributes(data, attributes, transformation, arguments=None):
        id_ = data.get('id')
        arguments = arguments if arguments else {}
        transformed_data = {}
        for attribute in attributes:
            value = data.get(attribute)
            try:
                transformed_data[attribute] = transformation(value, **arguments)
            except Exception:  # noqa
                LOGGER.error(f'Attribute :{attribute} with value: {value} for secret :{id_} cannot be transformed.')
        return transformed_data

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
        note_data = {'original_notes': data.get('notes', '')}
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
            LOGGER.error(f'Could not identify valid lines in the note of secret {secret_name} maybe it is corrupt?')
        return class_type, data

    @staticmethod
    def _parse_shared_folder(payload, encryption_key, rsa_key):
        stream = Stream(payload)
        folder = SharedFolderSchema()
        data = Vault._get_attribute_payload_data(stream, folder.attributes)
        data.update(Vault._transform_data_attributes(data,
                                                     folder.hex_decoded,
                                                     EncryptManager.decode_hex))
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
        data.update(Vault._transform_data_attributes(data,
                                                     folder.decoded_attributes,
                                                     lambda x: x.decode('utf-8')))
        return data

    def refresh(self):
        """Refreshes the vault by cleaning up the encrypted blob and the decrypted secrets and forcing the retrieval."""
        self._logger.info('Cleaning up local blob.')
        self._blob = None
        self._logger.info('Retrieving remote blob and decrypting secrets.')
        try:
            _ = self.blob
        except Exception:  # noqa
            self._logger.exception('Problem retrieving remote blob.')
            return False
        return True

    def save(self, path='.', name='vault.blob', timestamp=True):
        """Can save the downloaded blob.

        Args:
            path: The path to save the blob to, defaults to local directory.
            name: The name to save the blob as, defaults to "vault.blob".

        Returns:
            None.

        """
        name = f'{f"{int(time.time() * 10)}-" if timestamp else ""}{name}'
        with open(Path(path, name), 'wb', encoding='utf8') as ofile:
            ofile.write(self.blob)


@dataclass
class DecryptedVault:

    def __init__(self,  # pylint: disable=too-many-arguments
                 lastpass_instance,
                 encrypted_username,
                 attachments,
                 never_urls,
                 equivalent_domains,
                 url_rules,
                 secrets,
                 encryption_key,
                 folder_entries,
                 shared_folders):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self._lastpass = lastpass_instance
        self.encrypted_username = encrypted_username
        self.attachments = attachments
        self.never_urls = never_urls
        self.equivalent_domains = equivalent_domains
        self.url_rules = url_rules
        self.secrets = secrets
        self.encryption_key = encryption_key
        self.folder_entries = folder_entries
        self._folders = None
        self._shared_folders = shared_folders

    def _get_shared_folder_by_id(self, folder_id):
        return next((folder for folder in self._shared_folders if folder.id == folder_id), None)

    def delete_secret_by_id(self, id_):
        self.secrets = [secret for secret in self.secrets if secret.id != id_]
        self.clear_folders()

    def create_secret(self, secret_type, data):
        shared_folder = self._get_shared_folder_by_id(data.get('shared_folder_id'))
        secret = secret_type(self._lastpass, data, shared_folder)
        self.secrets.append(secret)
        self.clear_folders()
        return True

    def clear_folders(self):
        self._folders = None

    @property
    def folders(self):
        """All the folders of the vault.

        Returns:
            A list of all the folders of the vault.

        """
        if self._folders is None:
            root_folder_data, folders_data = self._parse_folder_groups(self.secrets)
            root_folder = Folder('\\',
                                 ('\\',),
                                 id=None,
                                 encryption_key=self.encryption_key,
                                 is_personal=True)
            root_folder.secrets.extend(root_folder_data.get('\\'))
            all_folders = [root_folder]
            all_folders.extend(self._get_folder_objects(folders_data, root_folder))
            self._folders = all_folders
        return self._folders

    @staticmethod
    def _parse_folder_groups(secrets):
        """Parses all folder structures by iterating over all secrets.

        There are three levels of folders. One is the root one that could hold parentless secrets, the second is the
        personal folders that only exist for the user and the third is the shared folders that are shared.

        Args:
            secrets: All the secrets to iterate over and deduct their directory structure.

        Returns:
            tuple: Data for the root folder, the personal folders and the shared folders.

        """
        root_folder_data = {'\\': []}
        folders_data = defaultdict(list)
        for secret in secrets:
            if not any([secret.group_id, secret.shared_folder]):
                root_folder_data['\\'].append(secret)
                continue
            if secret.group_id:
                split_path = tuple(secret.group.split('\\'))
                is_personal = True
                group_id = secret.group_id
            if secret.shared_folder:
                split_path = (tuple([secret.shared_folder.shared_name] + secret.group.split('\\'))
                              if secret.group else tuple([secret.shared_folder.shared_name]))
                is_personal = False
                group_id = secret.shared_folder.id
            folder_metadata = FolderMetadata(split_path,
                                             group_id,
                                             secret.encryption_key,
                                             is_personal=is_personal)
            folders_data[folder_metadata].append(secret)
        return root_folder_data, folders_data

    @staticmethod
    def _get_parent_folder(folder, folders):
        """Tries to identify the parent folder of a provided folder and return that from a list of folders.

        Args:
            folder: The folder to look the parent for.
            folders: A list of all the folders.

        Returns:
            The parent folder of the mentioned folder if a match is found, else None.

        """
        return next((parent_folder for parent_folder in folders
                     if tuple(folder.path[:-1]) == parent_folder.path), None)  # noqa

    @staticmethod
    def _get_folder_objects(secrets_by_path, root_folder=None):
        folder_objects = []
        for folder_metadata, secrets in sorted(secrets_by_path.items()):
            folder = Folder(folder_metadata.path[-1],
                            folder_metadata.path,
                            folder_metadata.id,
                            folder_metadata.encryption_key,
                            is_personal=folder_metadata.is_personal)
            folder.add_secrets(secrets)
            if len(folder.path) > 1:
                folder_parent = DecryptedVault._get_parent_folder(folder, folder_objects)
                if not folder_parent:
                    folder_parent = Folder(folder.path[-2],
                                           tuple(folder.path[:-1]),
                                           id=None,
                                           encryption_key=folder.encryption_key,
                                           is_personal=folder_metadata.is_personal)
                    folder_grandparent = DecryptedVault._get_parent_folder(folder_parent, folder_objects)
                    if folder_grandparent:
                        folder_grandparent.add_folder(folder_parent)
                        folder_parent.parent = folder_grandparent
                    folder_objects.append(folder_parent)
                folder.parent = folder_parent
                folder_parent.add_folder(folder)
            else:
                if root_folder:
                    folder.parent = root_folder
                    root_folder.add_folder(folder)
            folder_objects.append(folder)
        return folder_objects
