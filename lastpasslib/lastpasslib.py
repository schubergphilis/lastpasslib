#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: lastpasslib.py
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
Main code for lastpasslib.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

from base64 import b64encode
import datetime
import logging
from collections import defaultdict
import time
from xml.etree import ElementTree as Etree
from xml.etree.ElementTree import ParseError

import backoff
import requests
from dateutil.parser import parse
from requests import Session
import urllib

from lastpasslib.encryption import EncryptManager

from .datamodels import CompanyUser, Event, Folder, FolderMetadata, SharedFolder
from .lastpasslibexceptions import (ApiLimitReached,
                                    InvalidMfa,
                                    InvalidPassword,
                                    InvalidSecretType,
                                    MfaRequired,
                                    MultipleInstances,
                                    ServerError,
                                    UnexpectedResponse,
                                    UnknownIP,
                                    UnknownUsername,
                                    MobileDevicesRestricted)
from .secrets import SECURE_NOTE_TYPES
from .vault import Vault

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''08-02-2023'''
__copyright__ = '''Copyright 2023, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''lastpasslib'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class Lastpass:
    """Models the main service and exposes the vault object and helper methods to interact and retrieve data."""

    def __init__(self, username, password, mfa, domain='lastpass.com'):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self.domain = domain
        self.host = f'https://{domain}'
        self.username = username
        self._iteration_count = None
        self._vault = Vault(self, password)
        self._authenticated_response_data = None
        self.session = self._get_authenticated_session(username, mfa)
        self._monkey_patch_session()
        self._shared_folders_ = None
        self._folders = None
        self._decrypted_vault = None

    def _monkey_patch_session(self):
        """Gets original request method and overrides it with the patched one.

        Returns:
            Response: Response instance.

        """
        self.session.original_request = self.session.request
        self.session.request = self._patched_request

    @backoff.on_exception(backoff.expo,
                          ApiLimitReached,
                          max_time=60)
    def _patched_request(self, method, url, **kwargs):
        """Patch the original request method from requests.Sessions library.

        Args:
            method (str): HTTP verb as string.
            url (str): string.
            kwargs: keyword arguments.

        Raises:
            ApiLimitReached: Raised when the Lastpass API limit is reached.

        Returns:
            Response: Response instance.

        """
        self._logger.debug(f'{method.upper()} request to url :{url} with kwargs: {kwargs}.')
        response = self.session.original_request(method, url, **kwargs)  # noqa
        self._logger.debug(f'Response status: {response.status_code} with content: {response.content}.')
        if response.status_code == 429:
            self._logger.warning('Api is exhausted for endpoint, backing off.')
            raise ApiLimitReached
        return response

    @property
    def token(self):
        """The token returned to be used for api calls."""
        return self._authenticated_response_data.get('token')

    @property
    def csrf_token(self):
        """The csrf token required for some calls."""
        url = f'{self.host}/getCSRFToken.php'
        response = self.session.post(url, data='')
        if not response.ok:
            response.raise_for_status()
        return response.text

    @property
    def iteration_count(self):
        """The iteration count of the encryption for the vault."""
        if self._iteration_count is None:
            url = f'{self.host}/iterations.php'
            data = {'email': self.username}
            response = requests.post(url, data=data, timeout=10)
            if not response.ok:
                response.raise_for_status()
            self._iteration_count = response.json()
        return self._iteration_count

    @staticmethod
    def _validate_response(response):
        if not response.ok:
            response.raise_for_status()
        try:
            parsed_response = Etree.fromstring(response.content)
        except ParseError:
            raise UnexpectedResponse(response.text) from None
        error = parsed_response.find('error')
        if error is not None:
            exceptions = {
                'unknownemail': UnknownUsername,
                'user_not_exists': UnknownUsername,
                'password_invalid': InvalidPassword,
                'googleauthrequired': MfaRequired,
                'microsoftauthrequired': MfaRequired,
                'googleauthfailed': InvalidMfa,
                'microsoftauthfailed': InvalidMfa,
                'yubikeyrestricted': InvalidMfa,
                'unifiedloginresult': UnknownIP,
                'mobilerestricted': MobileDevicesRestricted,
            }
            messages = {
                'mobilerestricted': ('Mobile devices are restricted under "Advanced Settings" -> "Mobile Devices" '
                                     'under the lastpass vault. Please enable and allow accordingly for the tool to '
                                     'work.'),
                'unifiedloginresult': ('You should have received an email from lastpass to allow the current IP to '
                                       'access the vault, follow that link, provide access and run again.')
            }
            cause = error.attrib.get('cause')
            exception = exceptions.get(cause, ServerError)
            LOGGER.error(f'Got a server error :{cause}')
            message = messages.get(cause, error.attrib.get('message'))
            raise exception(message)
        return parsed_response

    @staticmethod
    def _extend_payload_for_mfa(mfa, payload):
        payload['otp'] = mfa
        conditions_for_yubikey = [len(mfa) == 44, str(mfa).isalpha(), str(mfa).islower()]
        if all(conditions_for_yubikey):
            LOGGER.debug('Identified mfa as yubikey.')
            payload['provider'] = 'yubikey'
        return payload

    def _get_authenticated_session(self, username, mfa=None, client_id=None):
        session = Session()
        payload = {'method': 'mobile',
                   'web': 1,
                   'xml': 1,
                   'username': username,
                   'hash': self._vault.hash,
                   'iterations': self.iteration_count}
        if mfa:
            payload = self._extend_payload_for_mfa(mfa, payload)
        if client_id:
            payload['imei'] = client_id
        headers = {'user-agent': 'lastpasslib'}
        response = requests.post(f'{self.host}/login.php', data=payload, headers=headers, timeout=10)
        parsed_response = self._validate_response(response)
        if parsed_response.tag == 'ok':
            data = parsed_response.attrib
            session.cookies.set('PHPSESSID', data.get('sessionid'), domain=self.domain)
            self._authenticated_response_data = data
        return session

    @property
    def _shared_folders(self):
        """A list of the shared folders of lastpass."""
        if self._shared_folders_ is None:
            url = f'{self.host}/getSharedFolderInfo.php'
            data = {'lpversion': '4.0',
                    'method': 'web',
                    'token': self.token}
            response = self.session.post(url, data=data)
            if not response.ok:
                response.raise_for_status()
            self._shared_folders_ = [SharedFolder(*data.values()) for data in response.json().get('folders')]
            # response.json().get('superusers') exposes a {uid: , key:} dictionary of superusers.
        return self._shared_folders_

    def _get_shared_folder_by_id(self, id_):
        """Gets a shared folder by id.

        Used to connect the shared folders with the appropriate secrets in the decryption process of the vault.

        Args:
            id_: The id to match the folder.

        Returns:
            A shared folder object if a match is found, else None

        """
        return next((folder for folder in self._shared_folders if folder.id == id_), None)

    def get_login_history_by_date(self, start_date=None, end_date=None):
        """Get login history events by a range of dates.

        Args:
            start_date: The start date of the range. Defaults to today if not provided.
            end_date: The end date of the range. Defaults to today if not provided.

        Returns:
            A list of login history events by the provided date range.

        """
        return self._get_history_by_date(start_date, end_date, 'logins')

    def get_event_history_by_date(self, start_date=None, end_date=None):
        """Get generic history events by a range of dates.

        Args:
            start_date: The start date of the range. Defaults to today if not provided.
            end_date: The end date of the range. Defaults to today if not provided.

        Returns:
            A list of generic history events by the provided date range.

        """
        return self._get_history_by_date(start_date, end_date, 'events')

    def get_company_users_by_email(self, email_part):
        """Gets a list of company users that match a fragment of the email.

        Args:
            email_part: The fragment of the email to match to.

        Returns:
            A list of company users that match the fragment provided.

        """
        params = {'q': email_part}
        url = f'{self.host}/typeahead_remote.php'
        response = self.session.post(url, params=params)
        if not response.ok:
            response.raise_for_status()
        return [CompanyUser(**item) for item in response.json()]

    def get_company_user_by_email(self, email):
        """Gets a company user that exactly match a provided email.

        Args:
            email: The email to match to.

        Returns:
            A company user object if a match is found, else None.

        """
        return next((user for user in self.get_company_users_by_email(email) if user.email.lower() == email.lower()),
                    None)

    def _get_history_by_date(self, start_date, end_date, event_type):
        date_format = '%Y-%m-%d'
        today = datetime.date.today().strftime(date_format)
        start_date = parse(start_date).strftime(date_format) if start_date else today
        end_date = parse(end_date).strftime(date_format) if end_date else today
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
                  'token': self.token}
        url = f'{self.host}/history.php'
        response = self.session.post(url, params=params, data=form_data)
        if not response.ok:
            response.raise_for_status()
        items = response.json().get('response', {}).get('value', {}).get('items', [])
        return [Event(*item.values()) for item in items]

    @property
    def decrypted_vault(self):
        if self._decrypted_vault is None:
            self._decrypted_vault = self._vault.decrypt_blob(self._vault.blob)
        return self._decrypted_vault

    @property
    def encrypted_username(self):
        """The encrypted username of the user."""
        return self.decrypted_vault.encrypted_username

    @property
    def attachments(self):
        """The attachments of the vault."""
        return self.decrypted_vault.attachments

    @property
    def never_urls(self):
        """The never urls of the vault."""
        return self.decrypted_vault.never_urls

    @property
    def equivalent_domains(self):
        """The equivalent domains of the vault."""
        return self.decrypted_vault.equivalent_domains

    @property
    def url_rules(self):
        """The url rules of the vault."""
        return self.decrypted_vault.url_rules

    @property
    def uid(self):
        """The uid of lastpass."""
        return self._authenticated_response_data.get('uid')

    @property
    def session_id(self):
        """The session ID."""
        return self._authenticated_response_data.get('sessionid')

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
            if secret.shared_folder:
                split_path = (tuple([secret.shared_folder.shared_name] + secret.group.split('\\'))
                              if secret.group else tuple([secret.shared_folder.shared_name]))
                is_personal = False
            folder_metadata = FolderMetadata(split_path,
                                             secret.group_id,
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

    def _get_folder_objects(self, secrets_by_path, root_folder=None):
        folder_objects = []
        for folder_metadata, secrets in sorted(secrets_by_path.items()):
            folder = Folder(folder_metadata.path[-1],
                            folder_metadata.path,
                            folder_metadata.id,
                            folder_metadata.encryption_key,
                            is_personal=folder_metadata.is_personal)
            folder.add_secrets(secrets)
            if len(folder.path) > 1:
                folder_parent = self._get_parent_folder(folder, folder_objects)
                if not folder_parent:
                    folder_parent = Folder(folder.path[-2],
                                           tuple(folder.path[:-1]),
                                           id=None,
                                           encryption_key=folder.encryption_key,
                                           is_personal=folder_metadata.is_personal)
                    folder_grandparent = self._get_parent_folder(folder_parent, folder_objects)
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

    def get_folder_by_name(self, name):
        """Gets a folder by name.

        Args:
            name: The name of the folder to match.

        Returns:
            The folder it matched on if there is one match only, None if no match found.

        Raises:
            MultipleInstances: If there is more than one match with the same name.

        """
        folders = [folder for folder in self.folders if folder.name == name]
        if not folders:
            return folders
        if len(folders) > 1:
            raise MultipleInstances(f'multiple instances of {name} found')
        return folders.pop()

    def get_folder_by_path(self, path: str) -> Folder:
        """Gets a folder by path.

        Args:
            path (str): A string with '\\' as seperator.

        Returns:
            Folder: The first folder it matched on based on path. None if no match found.
        """
        return next((folder for folder in self.folders if folder.path == tuple(path.split('\\'))), None)

    @property
    def folders(self):
        """All the folders of the vault.

        Returns:
            A list of all the folders of the vault.

        """
        if self._folders is None:
            root_folder_data, folders_data = self._parse_folder_groups(self.get_secrets())
            root_folder = Folder('\\',
                                 ('\\',),
                                 id=None,
                                 encryption_key=self._vault._key,
                                 is_personal=True)
            root_folder.secrets.extend(root_folder_data.get('\\'))
            all_folders = [root_folder]
            all_folders.extend(self._get_folder_objects(folders_data, root_folder))
            self._folders = all_folders
        return self._folders

    @property
    def root_folder(self):
        """The root folder of the lastpass vault.

        Holds all sub folders and secrets saved in.

        Returns:
            Folder: The root folder.

        """
        return next((folder for folder in self.folders if folder.name == '\\'), None)

    @property
    def personal_folders(self):
        """Retrieves all folders of the vault that are personal and not shared.

        Returns:
            list: A list of personal folders.

        """
        return [folder for folder in self.folders if all([folder.is_personal,
                                                          len(folder.path) == 1])]

    @property
    def shared_folders(self):
        """Retrieves all shared folders of the vault.

        Returns:
            list: A list of shared folders.

        """
        shared_names = [folder.shared_name for folder in self._shared_folders]
        return [folder for folder in self.folders
                if all([not folder.is_personal,
                        folder.name in shared_names,
                        len(folder.path) == 1])]

    def get_secrets(self, filter_=None):
        """Gets secrets from the vault.

        Args:
            filter_: The secret type or types to filter.

        Returns:
            list: A list of secrets matching the filter or all secrets of the vault.

        """
        filter_ = self._validate_filter(filter_)
        return [secret for secret in self.decrypted_vault.secrets if secret.type in filter_]

    def get_secret_by_name(self, name):
        """Gets a secret from the vault by name.

        Args:
            name: The name to match on, case-sensitive.

        Returns:
            The secret if a match is found, else None.

        Raises:
            MultipleInstances: If more than one password is found with the same name.

        """
        secrets = self.get_secrets_by_name(name)
        if not secrets:
            return None
        if len(secrets) > 1:
            raise MultipleInstances(f'More than one secrets with name {name} exist.')
        return secrets.pop()

    def get_secret_by_id(self, id_):
        """Gets a secret from the vault by id.

        Args:
            id_: The id to match on.

        Returns:
            The secret if a match is found, else None.

        """
        return next((secret for secret in self.get_secrets() if secret.id == str(id_)), None)

    def get_secrets_by_name(self, name, filter_=None):
        """Gets secrets from the vault matching a name.

        Args:
            name: The name to match on, case-sensitive.
            filter_: The type of secret to filter on.

        Returns:
            list: A list of secrets if they match the name, an empty list otherwise.

        """
        return [secret for secret in self.get_secrets(filter_) if secret.name == name]

    def get_secrets_by_group(self, group_name, filter_=None):
        """Gets secrets from the vault for the specified group.

        Args:
            group_name: The name to match on, case-sensitive.
            filter_: The type of secret to filter on.

        Returns:
            list: A list of secrets if they match the group name, an empty list otherwise.

        """
        return [secret for secret in self.get_secrets(filter_) if secret.group == group_name]

    def get_secrets_by_shared_folder(self, folder_name, filter_=None):
        """Gets secrets from the vault for the specified shared folder.

        Args:
            folder_name: The name to match on, case-sensitive.
            filter_: The type of secret to filter on.

        Returns:
            list: A list of secrets of the shared folder, an empty list otherwise.

        """
        return [secret for secret in self.get_secrets(filter_)
                if secret.shared_folder and secret.shared_folder.shared_name == folder_name]

    def get_passwords_with_password_updated_before_date(self, date):
        """Gets passwords with passwords updates before the given date.

        Args:
            date: The date to match with. Parsing is applied on the date so any sane format will work.
                example: '22 sep 2022' or '22-09-2002' or '22/09/2022' should all work fine.
                To avoid ambiguity between US and EU date format a format with a named month is preferred.

        Returns:
            A list of passwords that their password field had been updated before the given date.

        """
        date = parse(date)
        return [secret for secret in self.get_passwords()
                if secret.last_password_change_datetime < date]

    def get_secure_notes_updated_before_date(self, date):
        """Gets secure notes with updates before the given date.

        Args:
            date: The date to match with. Parsing is applied on the date so any sane format will work.
                example: '22 sep 2022' or '22-09-2002' or '22/09/2022' should all work fine.
                To avoid ambiguity between US and EU date format a format with a named month is preferred.

        Returns:
            A list of secure notes that have been updated before the given date.

        """
        date = parse(date)
        return [secret for secret in self.get_secure_notes()
                if secret.last_modified_datetime < date]

    def get_secrets_with_attachments(self):
        """Gets secrets with attachments.

        Returns:
            list: A list of secrets with attachments.

        """
        return [secret for secret in self.get_secrets() if secret.has_attachment]

    def get_secrets_shared_directly(self):
        """Gets secrets that have been shared directly and not as part of a shared folder.

        Returns:
            list: A list of secrets that have been shared directly.

        """
        return [secret for secret in self.get_secrets() if secret.has_been_shared]

    def delete_secret_by_name(self, name):
        """Deletes a secret from the vault by name.

        Args:
            name: The name to match on, case-sensitive.

        Returns:
            bool: True on success, False otherwise.

        Raises:
            MultipleInstances: If more than one password is found with the same name.

        """
        secret = self.get_secret_by_name(name)
        if not secret:
            self._logger.error(f'Secret with name "{name}" not found.')
            return False
        return secret.delete()

    def delete_secret_by_id(self, id_):
        """Deletes a secret from the vault by id.

        Args:
            id_: The id to match on

        Returns:
            bool: True on success, False otherwise.

        Raises:
            MultipleInstances: If more than one password is found with the same name.

        """
        secret = self.get_secret_by_id(id_)
        if not secret:
            self._logger.error(f'Secret with id "{id_}" not found.')
            return False
        return secret.delete()

    def get_passwords(self):
        """Gets only the passwords from the vault.

        Returns:
            A list of password type secrets.

        """
        return self.get_secrets(filter_='Password')

    def get_passwords_by_name(self, name):
        """Gets passwords from the vault matching a name.

        Args:
            name: The name to match on, case-sensitive.
            filter_: The type of secret to filter on.

        Returns:
            list: A list of passwords if they match the name, an empty list otherwise.

        """
        return [password for password in self.get_passwords() if password.name == name]

    def get_password_by_name(self, name):
        """Gets password from the vault matching a name.

        Args:
            name: The name to match on, case-sensitive.
            filter_: The type of secret to filter on.

        Returns:
            list: A list of passwords if they match the name, an empty list otherwise.

        """
        password = self.get_passwords_by_name(name)
        if not password:
            return None
        if len(password) > 1:
            raise MultipleInstances(f'More than one password with name {name} exist.')
        return password.pop()

    def get_password_by_id(self, id_):
        """Gets a password from the vault by id.

        Args:
            id_: The id to match on.

        Returns:
            The password if a match is found, else None.

        """
        return next((password for password in self.get_passwords() if password.id == str(id_)), None)

    def get_passwords_by_group(self, group_name):
        """Gets passwords from the vault for the specified group.

        Args:
            group_name: The name to match on, case-sensitive.

        Returns:
            list: A list of passwords if they match the group name, an empty list otherwise.

        """
        return self.get_secrets_by_group(group_name, filter_='Password')

    def get_passwords_by_shared_folder(self, folder_name):
        """Gets passwords from the vault for the specified shared folder.

        Args:
            folder_name: The name to match on, case-sensitive.

        Returns:
            list: A list of passwords of the shared folder, an empty list otherwise.

        """
        return self.get_secrets_by_shared_folder(folder_name, filter_='Password')

    def get_passwords_with_attachments(self):
        """Gets passwords with attachments.

        Returns:
            list: A list of passwords with attachments.

        """
        return [secret for secret in self.get_passwords() if secret.has_attachment]

    def delete_password_by_name(self, name):
        """Deletes a password from the vault by name.

        Args:
            name: The name to match on, case-sensitive.

        Returns:
            bool: True on success, False otherwise.

        Raises:
            MultipleInstances: If more than one password is found with the same name.

        """
        password = self.get_password_by_name(name)
        if not password:
            self._logger.error(f'Password with name "{name}" not found.')
            return False
        return password.delete()

    def delete_password_by_id(self, id_):
        """Deletes a password from the vault by id.

        Args:
            id_: The id to match on

        Returns:
            bool: True on success, False otherwise.

        Raises:
            MultipleInstances: If more than one password is found with the same name.

        """
        password = self.get_password_by_id(id_)
        if not password:
            self._logger.error(f'Password with id "{id_}" not found.')
            return False
        return password.delete()

    def get_secure_notes(self):
        """Gets only secure notes for the vault.

        Returns:
            A list of secure note type secrets.

        """
        return self.get_secrets(filter_=SECURE_NOTE_TYPES)

    def get_secure_notes_by_name(self, name):
        """Gets secure notes from the vault matching a name.

        Args:
            name: The name to match on, case-sensitive.
            filter_: The type of secret to filter on.

        Returns:
            list: A list of secure notes if they match the name, an empty list otherwise.

        """
        return [secure_note for secure_note in self.get_secure_notes() if secure_note.name == name]

    def get_secure_note_by_name(self, name):
        """Gets secure note from the vault matching a name.

        Args:
            name: The name to match on, case-sensitive.

        Returns:
            list: A list of secure note if they match the name, an empty list otherwise.

        """
        secure_note = self.get_secure_notes_by_name(name)
        if not secure_note:
            return None
        if len(secure_note) > 1:
            raise MultipleInstances(f'More than one secure note with name {name} exist.')
        return secure_note.pop()

    def get_secure_note_by_id(self, id_):
        """Gets a secure note from the vault by id.

        Args:
            id_: The id to match on.

        Returns:
            The secure note if a match is found, else None.

        """
        return next((secure_note for secure_note in self.get_secure_notes() if secure_note.id == str(id_)), None)

    def get_secure_notes_by_group(self, group_name):
        """Gets secure notes from the vault for the specified group.

        Args:
            group_name: The name to match on, case-sensitive.

        Returns:
            list: A list of secure notes if they match the group name, an empty list otherwise.

        """
        return self.get_secrets_by_group(group_name, filter_=SECURE_NOTE_TYPES)

    def get_secure_notes_by_shared_folder(self, folder_name):
        """Gets secure notes from the vault for the specified shared folder.

        Args:
            folder_name: The name to match on, case-sensitive.

        Returns:
            list: A list of secure notes of the shared folder, an empty list otherwise.

        """
        return self.get_secrets_by_shared_folder(folder_name, filter_=SECURE_NOTE_TYPES)

    def get_secure_notes_with_attachments(self):
        """Gets secure notes with attachments.

        Returns:
            list: A list of secure notes with attachments.

        """
        return [secret for secret in self.get_secure_notes() if secret.has_attachment]

    def delete_secure_note_by_name(self, name):
        """Deletes a secure note from the vault by name.

        Args:
            name: The name to match on, case-sensitive.

        Returns:
            bool: True on success, False otherwise.

        Raises:
            MultipleInstances: If more than one secure note is found with the same name.

        """
        secure_note = self.get_secure_note_by_name(name)
        if not secure_note:
            self._logger.error(f'Secure note with name "{name}" not found.')
            return False
        return secure_note.delete()

    def delete_secure_note_by_id(self, id_):
        """Deletes a secure notes from the vault by id.

        Args:
            id_: The id to match on

        Returns:
            bool: True on success, False otherwise.

        Raises:
            MultipleInstances: If more than one secure note is found with the same name.

        """
        secure_note = self.get_secure_note_by_id(id_)
        if not secure_note:
            self._logger.error(f'Secure notes with id "{id_}" not found.')
            return False
        return secure_note.delete()

    def get_attachments(self):
        """Gets all attachments from all secrets in the vault.

        Returns:
            list: A list of attachment objects from all secrets of the vault.

        """
        attachments = []
        for secret in self.get_secrets_with_attachments():
            for attachment in secret.attachments:
                attachments.append(attachment)
        return attachments

    def decrypt_blob(self, blob):
        """Decrypts a provided blob of a vault back up and returns the decrypted blob.

        Args:
            blob: The blob to decrypt.

        Returns:
            DecryptedBlob: The decrypted blob.

        """
        try:
            self._decrypted_vault = self._vault.decrypt_blob(blob)
        except Exception:
            self._logger.exception('Unable to decrypt blob')
            return False
        return True

    @staticmethod
    def _validate_filter(filter_):
        all_types = SECURE_NOTE_TYPES + ['Password']
        filter_ = filter_ or all_types
        if not isinstance(filter_, (tuple, list)):
            filter_ = [filter_]
        diff = set(filter_) - set(all_types)
        if diff:
            raise InvalidSecretType(diff)
        return filter_

    def refresh(self):
        """Refreshes the vault by getting the blob again and decrypting everything.

        Returns:
            True on success, False otherwise.

        """
        self._decrypted_vault = None
        return self._vault.refresh()

    def save_vault_blob(self, path='.', name='vault.blob'):
        """Can save the downloaded blob.

        Args:
            path: The path to save the blob to, defaults to local directory.
            name: The name to save the blob as, defaults to "vault.blob".

        Returns:
            None.

        """
        return self._vault.save(path, name)

    def logout(self):
        """Logs out of the session."""
        params = {'skip_prompt': 1,
                  'from_uri': '/'}
        url = f'{self.host}/logout'
        response = self.session.get(url, params=params)
        if not response.ok:
            response.raise_for_status()
        return response.ok

    def __del__(self):
        try:
            return self.logout()
        except Exception as exc:
            self._logger.debug(f'Error closing session, response: {exc}')
            return False

    def create_secret(self, 
                     name:str,
                     url:str = None,
                     folder_path:str = None,
                     username:str = None,
                     password:str = None,
                     group:str = None,
                     totp:str = None,
                     notes:str = None,
                     pwprotect:bool = False,
                     auto_login:bool = False,
                     autofill:bool = False,
                     favorite:bool = False) -> bool:
        """
        Creates a secret. 
        Depending on the folder, a different encryption key is used. 

        Args:
            name (str): name
            url (str, optional): url. Defaults to None.
            folder_path (str, optional): folder. Defaults to None.
            username (str, optional): username. Defaults to None.
            password (str, optional): password. Defaults to None.
            totp (str, optional): totp. Defaults to None.
            notes (str, optional): notes. Defaults to None.
            pwprotect (bool, optional): pwprotect. Defaults to False.
            auto_login (bool, optional): auto_login. Defaults to False.
            autofill (bool, optional): autofill. Defaults to False.
            favorite (bool, optional): favorite. Defaults to False.
            encryption_key (bytes, optional): encryption_key. Defaults to None.
            iv (bytes, optional): iv. Defaults to None.

        Returns:
            bool: True at success, False at failure.
        """

        if not self.folders:
            print('Fetching secrets & folders, this might take a minute...')
            self.folders
        
        base_path = ''
        grouping_path = ''
        if folder_path:
            base_path, *grouping_path = folder_path.split('\\', 1)

        folder = self.get_folder_by_path(base_path)
        if not folder:
            self._logger.error(f'No folder found for path {base_path}')
            return False

        iv = EncryptManager.create_random_iv()

        if not grouping_path:
            grouping = ''
        elif folder.is_personal:
            grouping = self.encrypt_and_encode_payload(folder_path, folder.encryption_key, iv)
        else:
            grouping = self.encrypt_and_encode_payload(grouping_path[0], folder.encryption_key, iv)                               

        payload = {
            'aid': '0',
            'ajax': '1',
            'auto': '1',
            'autofill': 'on' if autofill else '',
            'autologin': 'on' if auto_login else '',
            'encuser': urllib.parse.quote(self.encrypted_username, safe=''),
            'extjs': '1',
            'extra': self.encrypt_and_encode_payload(notes, folder.encryption_key, iv),
            'fav': 'on' if favorite else '',
            'folder': 'none',
            'grouping': grouping,
            'localupdate': '1',
            'method': 'cr',
            'n': name.encode('utf-8').hex(),
            'name': self.encrypt_and_encode_payload(name, folder.encryption_key, iv),
            'password': self.encrypt_and_encode_payload(password, folder.encryption_key, iv),
            'pwprotect': 'on' if pwprotect else '',
            'requesthash': urllib.parse.quote(self.encrypted_username, safe=''),
            'requestsrc': 'cr',
            'sentms': f"{time.time_ns() // 1_000_000}",
            'sharedfolderid': '' if folder.is_personal else folder.id,
            'source': 'vault',
            'token': urllib.parse.quote(self.csrf_token, safe=''),
            'totp': self.encrypt_and_encode_payload(totp, folder.encryption_key, iv),
            'urid': '0',
            'url': url.encode().hex() if url else '', 
            'username': self.encrypt_and_encode_payload(username, folder.encryption_key, iv),
        }

        headers = {'content-type': 'application/x-www-form-urlencoded'}
        payload_string = "&".join([f'{key}={value}' for key, value in payload.items()])
        url = f'{self.host}/show.php'
        response = self.session.post(url, headers=headers, data=payload_string)
        if not response.ok:
            self._logger.error(response.json())
        return True if response.ok else False

    def create_secure_note(self, 
                          name:str,
                          folder_path:str = None,
                          notes:str = None,
                          favorite:bool = False) -> bool:

        if not self.folders:
            print('Fetching secrets & folders, this might take a minute...')
            self.folders
        
        split_folder_path = folder_path.split('\\')
        folder = self.get_folder_by_path(split_folder_path[0])
        if not folder:
            self._logger.error(f'No folder found for path {split_folder_path[0]}')
            return False

        iv = EncryptManager.create_random_iv()
        if folder.is_personal:
            grouping = self.encrypt_and_encode_payload(folder_path, folder.encryption_key, iv)
        else:
            grouping = '' if 2 > len(split_folder_path) else \
                        self.encrypt_and_encode_payload('\\'.join(split_folder_path[1:]), folder.encryption_key, iv)                               

        payload = {
            'aid': '0',
            'auto': '1',
            'ajax': '1',
            'encuser': urllib.parse.quote(self.encrypted_username, safe=''),
            'extjs': '1',
            'extra': self.encrypt_and_encode_payload(notes, folder.encryption_key, iv),
            'fav': 'on' if favorite else '',
            'grouping': grouping,
            'hexName': name.encode('utf-8').hex(),
            'localupdate': '1',
            'method': 'cr',
            'n': name.encode('utf-8').hex(),
            'name': self.encrypt_and_encode_payload(name, folder.encryption_key, iv),
            'notetype': 'Generic',
            'password': '',
            'requesthash': urllib.parse.quote(self.encrypted_username, safe=''),
            'requestsrc': 'cr',
            'sentms': f"{time.time_ns() // 1_000_000}",
            'sharedfolderid': '' if folder.is_personal else folder.id,
            'source': 'vault',
            'template': '',
            'u': '',
            'url': '',
            'username': '',
            'totp': '',
            'token': urllib.parse.quote(self.csrf_token, safe=''),
        }

        headers = {'content-type': 'application/x-www-form-urlencoded'}
        payload_string = "&".join([f'{key}={value}' for key, value in payload.items()])
        url = f'{self.host}/show.php'
        response = self.session.post(url, headers=headers, data=payload_string)
        if not response.ok:
            self._logger.error(response.json())
        return True if response.ok else False


    def encrypt_and_encode_payload(self, payload:str, encryption_key:str, iv=None) -> str:
        """cbc encrypting and encoding a payload 

        Args:
            payload (str): _description_
            encryption_key (str): _description_
            iv (_type_, optional): _description_. Defaults to None.

        Returns:
            str: _description_
        """
        if not all([payload and encryption_key]):
            return ''
        if not iv:
            iv = EncryptManager.create_random_iv()
        encrypted_attribute = EncryptManager.encrypt_aes256_cbc(iv, payload.encode(), encryption_key)
        url_encoded_data = urllib.parse.quote(f'{b64encode(iv).decode("utf-8")}|{b64encode(encrypted_attribute).decode("utf-8")}', safe='')
        return f'!{url_encoded_data}'