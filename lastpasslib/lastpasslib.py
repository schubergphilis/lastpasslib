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
from xml.etree import ElementTree as Etree
from xml.etree.ElementTree import ParseError

import backoff
import requests
from dateutil.parser import parse
from requests import Session

from .datamodels import Event, SharedFolder, CompanyUser
from .lastpasslibexceptions import (ApiLimitReached,
                                    InvalidMfa,
                                    InvalidPassword,
                                    MfaRequired,
                                    ServerError,
                                    UnknownUsername,
                                    UnexpectedResponse)
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
        self._shared_folders = None

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
                'user_not_exists': UnknownUsername,
                'password_invalid': InvalidPassword,
                'googleauthrequired': MfaRequired,
                'microsoftauthrequired': MfaRequired,
                'googleauthfailed': InvalidMfa,
                'microsoftauthfailed': InvalidMfa,
                'yubikeyrestricted': InvalidMfa,
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
        response = requests.post(f'{self.host}/login.php', data=body, headers=headers, timeout=10)
        parsed_response = self._validate_response(response)
        if parsed_response.tag == 'ok':
            data = parsed_response.attrib
            session.cookies.set('PHPSESSID', data.get('sessionid'), domain=self.domain)
            self._authenticated_response_data = data
        return session

    @property
    def shared_folders(self):
        """A list of the shared folders of lastpass."""
        if self._shared_folders is None:
            url = f'{self.host}/getSharedFolderInfo.php'
            data = {'lpversion': '4.0',
                    'method': 'web',
                    'token': self.token}
            response = self.session.post(url, data=data)
            if not response.ok:
                response.raise_for_status()
            self._shared_folders = [SharedFolder(*data.values()) for data in response.json().get('folders')]
            # response.json().get('superusers') exposes a {uid: , key:} dictionary of superusers.
        return self._shared_folders

    def get_shared_folder_by_id(self, id_):
        """Gets a shared folder by id.

        Used to connect the shared folders with the appropriate secrets in the decryption process of the vault.

        Args:
            id_: The id to match the folder.

        Returns:
            A shared folder object if a match is found, else None

        """
        return next((folder for folder in self.shared_folders if folder.id == id_), None)

    @property
    def vault(self):
        """The vault object that exposes the secrets and ways to interact with it."""
        return self._vault

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
        """Gets a company user that exactlty match a provided email.

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
        return self.logout()
