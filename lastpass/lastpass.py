import datetime
from xml.etree import ElementTree as etree
from xml.etree.ElementTree import ParseError

import requests
from dateutil.parser import parse
from requests import Session

from .datamodels import AccountHistory, SharedFolder
from .entities import Vault
from .lastpassexceptions import (InvalidMfa,
                                 InvalidPassword,
                                 MfaRequired,
                                 ServerError,
                                 UnknownUsername,
                                 UnexpectedResponse)


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
                  'token': self._authenticated_response_data.get('token')}
        url = f'{self.host}/history.php'
        response = self._session.post(url, params=params, data=form_data)
        if not response.ok:
            response.raise_for_status()
        items = response.json().get('response', {}).get('value', {}).get('items', [])
        return [AccountHistory(*item.values()) for item in items]

