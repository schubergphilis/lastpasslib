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

import datetime
import logging
from collections import defaultdict
from xml.etree import ElementTree as Etree
from xml.etree.ElementTree import ParseError

import backoff
import requests
from dateutil.parser import parse
from requests import Session

from .datamodels import Event, SharedFolder, CompanyUser, Folder
from .lastpasslibexceptions import (ApiLimitReached,
                                    InvalidMfa,
                                    InvalidPassword,
                                    MfaRequired,
                                    ServerError,
                                    UnknownUsername,
                                    UnexpectedResponse,
                                    InvalidSecretType,
                                    MultipleInstances,
                                    UnknownIP)
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
                'unifiedloginresult': UnknownIP
            }
            exception = exceptions.get(error.attrib.get('cause'), ServerError)
            LOGGER.error(f'Got a server error :{error.attrib.get("cause")}')
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
        response = requests.post(f'{self.host}/login.php', data=body, headers=headers, timeout=10)
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
        personal_folders_data = defaultdict(list)
        shared_folders_data = defaultdict(lambda: defaultdict(list))
        for secret in secrets:
            split_path = tuple(secret.group.split('\\'))
            if secret.group_id:
                personal_folders_data[split_path].append(secret)
            elif secret.shared_folder:
                shared_folders_data[secret.shared_folder.shared_name][split_path].append(secret)
            else:
                root_folder_data['\\'].append(secret)
        return root_folder_data, personal_folders_data, shared_folders_data

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

    def _get_folder_objects(self, secrets_by_path, root_folder=None, is_personal=False):
        folder_objects = []
        for folder_path, secrets in sorted(secrets_by_path.items()):
            folder = Folder(folder_path[-1], folder_path, is_personal=is_personal)
            folder.add_secrets(secrets)
            if len(folder.path) > 1:  #
                folder_parent = self._get_parent_folder(folder, folder_objects)
                if not folder_parent:
                    folder_parent = Folder(folder.path[-2], tuple(folder.path[:-1]), is_personal=is_personal)
                    parent_folder = self._get_parent_folder(folder_parent, folder_objects)
                    if not parent_folder:
                        continue
                    parent_folder.add_folder(folder_parent)
                    folder_parent.parent = parent_folder
                    folder_objects.append(folder_parent)
                folder.parent = folder_parent
                folder_parent.add_folder(folder)
            else:
                if root_folder:
                    folder.parent = root_folder
                    root_folder.add_folder(folder)
            folder_objects.append(folder)
        return folder_objects

    @staticmethod
    def _get_shared_folder_objects(folder_name, folders):
        """Normalises the folder structure of a shared folder.

         Prepends the shared folder name in the path of all the children folders making the structure one level less.

        Args:
            folder_name: The name of the shared folder.
            folders: The list of all folders.

        Returns:
            A new structure for all children folders of a shared folder with the shared folder name part of their path.

        """
        root_secrets = folders.get(('',), [])
        if root_secrets:
            del folders[('',)]
        folders = {(folder_name,) + folder: secrets for folder, secrets in folders.items()}
        folders.update({(folder_name,): root_secrets})
        return folders

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

    @property
    def folders(self):
        """All the folders of the vault.

        Returns:
            A list of all the secrets of the vault.

        """
        if self._folders is None:
            root_folder_data, personal_folders, shared_folders = self._parse_folder_groups(self.get_secrets())
            root_folder = Folder('\\', ('\\',), is_personal=True)
            root_folder.secrets.extend(root_folder_data.get('\\'))
            all_folders = [root_folder]
            all_folders.extend(self._get_folder_objects(personal_folders, root_folder, is_personal=True))
            for name, folders in shared_folders.items():
                shared_folder = self._get_shared_folder_objects(name, folders)
                all_folders.extend(self._get_folder_objects(shared_folder, root_folder))
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

    def get_secret_by_id(self, id_):
        """Gets a secret from the vault by id.

        Args:
            id_: The id to match on.

        Returns:
            The secret if a match is found, else None.

        """
        return next((secret for secret in self.get_secrets() if secret.id == id_), None)

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

    def get_passwords(self):
        """Gets only the passwords from the vault.

        Returns:
            A list of password type secrets.

        """
        return self.get_secrets(filter_='Password')

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

    def get_secure_notes(self):
        """Gets only secure notes for the vault.

        Returns:
            A list of secure note type secrets.

        """
        return self.get_secrets(filter_=SECURE_NOTE_TYPES)

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
