import logging
from copy import copy
from datetime import datetime

from .datamodels import History
from .decryption import Decoder

LOGGER_BASENAME = 'secrets'
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class Secret:
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
