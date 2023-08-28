#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: secrets.py
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
Main code for secrets.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import base64
from dataclasses import dataclass
import logging
import time
from copy import copy
from datetime import datetime
from pathlib import Path
from dateutil.parser import parse

from .configuration import LASTPASS_VERSION
from .datamodels import History, ShareAction
from .encryption import EncryptManager
import urllib

LOGGER_BASENAME = 'secrets'
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


@dataclass
class History:
    """Models data of a history event on the server."""

    date: str
    value: str
    person: str

    @property
    def datetime(self):
        """Datetime object of the date."""
        return parse(self.date)

    def __str__(self):
        attributes = ['date', 'person', 'value']
        values = "\n".join([f'{attribute}: {getattr(self, attribute)}' for attribute in attributes])
        return f'{values}\n\n'


@dataclass
class ShareAction:
    """Models data of a share action of a secret."""

    company_username: str
    date: str
    email: str
    give: str
    share_date: str
    state: str
    _uid: str

    @property
    def id(self):
        """ID of the share action, correlates with the ID of the user part of the share."""
        return self._uid

    @property
    def share_datetime(self):
        """Datetime object of the share date."""
        return parse(self.share_date)

    @property
    def datetime(self):
        """Datetime object of the date."""
        return parse(self.date)

    @property
    def accepted(self):
        """Boolean of the accepted status of the share."""
        return bool(int(self.state))

    @property
    def given(self):
        """Boolean of the given status of the share."""
        return bool(int(self.give))

class Secret:
    """Models the secret and exposes the main attributes that are shared across Passwords and Secure Notes."""

    def __init__(self, lastpass_instance, data, shared_folder=None):
        self._logger = logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')
        self._lastpass = lastpass_instance
        self._data = data
        self._shared_folder = shared_folder
        self._attachments = []
        self._shared_to_people = None

    @property
    def type(self):
        """The type of the secret."""
        return self.__class__.__name__

    @property
    def encryption_key(self):
        """The encryption key that is used on the encrypted data of the secret."""
        return self._data.get('encryption_key')

    @property
    def attachment_encryption_key(self):
        """The attachment encryption key if any."""
        return self._data.get('attachment_encryption_key')

    @property
    def created_datetime(self):
        """A datetime object of the created at date of the secret."""
        return datetime.fromtimestamp(int(self._data.get('created_gmt')))

    @property
    def is_deleted(self):
        """Flag of the deletion state of the secret."""
        return self._data.get('deleted')

    @property
    def is_favorite(self):
        """Is favorite flag."""
        return self._data.get('is_favorite')

    @property
    def group(self):
        """Group name of the secret."""
        return self._data.get('group')

    @property
    def group_id(self):
        """Group id of the secret."""
        return self._data.get('group_id')

    @property
    def has_attachment(self):
        """Flag of whether the secret has attachments."""
        return bool(self._data.get('has_attachment'))

    @property
    def has_been_shared(self):
        """Flag of whether the secret has been shared with people."""
        return self._data.get('has_been_shared')

    @property
    def id(self):
        """ID."""
        return self._data.get('id')

    @property
    def is_individual_share(self):
        """Flag of whether the secret is an individual share or a share as part of a shared folder."""
        return self._data.get('is_individual_share')

    @property
    def is_secure_note(self):
        """Flag of whether the secret is a secure note."""
        return self._data.get('is_secure_note')

    @property
    def last_modified_datetime(self):
        """A datetime object of the last modified date of the secret."""
        return datetime.fromtimestamp(int(self._data.get('last_modified_gmt')))

    @property
    def last_password_change_datetime(self):
        """A datetime object of the last password change of the secret, relevant for Passwords."""
        return datetime.fromtimestamp(int(self._data.get('last_password_change_gmt')))

    @property
    def last_touch_datetime(self):
        """A datetime object of the last touch date of the secret."""
        return datetime.fromtimestamp(int(self._data.get('last_touch_timestamp')))

    @property
    def name(self):
        """Name."""
        return self._data.get('name')

    @property
    def shared_folder(self):
        """A shared folder object of the parent share folder if any else None."""
        return self._shared_folder

    @property
    def is_password_protected(self):
        """Flag of whether the secret is password protected."""
        return self._data.get('is_password_protected')

    @property
    def shared_from_id(self):
        """The id of the user sharing the secret if it is an individual share."""
        return self._data.get('shared_from_id')

    @property
    def attachments(self):
        """The attachments of the secret if any."""
        return self._attachments

    def add_attachment(self, attachment):
        """Adds an attachment to the list of attachments on the secret.

        Used as part of the secret decryption process by the vault object adding all relevant attachments to the
        appropriate secret.

        Args:
            attachment: The attachment to add to the secret.

        Returns:
            None

        """
        self._attachments.append(attachment)

    def delete(self):
        """Deletes the secret from Lastpass."""
        url = f'{self._lastpass.host}/show.php'
        data = {
            'aid': self.id,
            'delete': '1',
            'encuser': self._lastpass.encrypted_username,
            'requesthash': self._lastpass.encrypted_username,
            'sentms': f"{time.time_ns() // 1_000_000}",
            'token': self._lastpass.token
        }
        response = self._lastpass.session.post(url, data=data, timeout=5)
        if not response.ok:
            self._logger.error(f'Response status: {response.status_code} with content: {response.content}.')
            return False
        self._lastpass.decrypted_vault.secrets = [
            secret
            for secret in self._lastpass.decrypted_vault.secrets
            if secret.id != self.id
        ]
        return True

    @property
    def shared_to_people(self):
        """List of people the secret has been shared with."""
        if not self.has_been_shared:
            return []
        if self._shared_to_people is None:
            url = f'{self._lastpass.host}/getSentShareInfo.php'
            data = {'aid': self.id,
                    'lpversion': LASTPASS_VERSION,
                    'method': 'cr',
                    'token': self._lastpass.token}
            response = self._lastpass.session.post(url, data=data)
            response.raise_for_status()
            sent = response.json().get('sent')
            if not sent:
                return []
            action_attributes = ['companyUserName', 'date', 'email', 'give', 'sharedate', 'state', 'uid']
            actions = sent.get(self.id)
            self._shared_to_people = [ShareAction(*[action.get(attribute) for attribute in action_attributes])
                                      for action in actions]
        return self._shared_to_people

    @property
    def url(self):
        """The url of the secret."""
        return self._data.get('url')


class FolderEntry(Secret):

    @property
    def name(self):
        return self.group


class Password(Secret):
    """Models a password and exposes appropriate attributes."""

    def __init__(self, lastpass_instance, data, shared_folder=None):
        super().__init__(lastpass_instance, data, shared_folder)
        self._note_history = None
        self._username_history = None
        self._password_history = None

    @property
    def action(self):
        """Action of the password if any."""
        return self._data.get('action')

    @property
    def auto_login(self):
        """Flag set if auto login is set."""
        return self._data.get('auto_login')

    @property
    def is_generated_password(self):
        """Flag if this is an auto generated password."""
        return self._data.get('generated_password')

    @property
    def mfa_seed(self):
        """The mfa seed of the password if set."""
        return self._data.get('mfa_seed')

    @property
    def never_autofill(self):
        """Flag whether the autofill is set."""
        return self._data.get('never_autofill')

    @property
    def notes(self):
        """The notes of the password."""
        return self._data.get('notes')

    @property
    def password(self):
        """The password field of the password."""
        return self._data.get('password')

    @property
    def username(self):
        """The username field of the password."""
        return self._data.get('username')

    @property
    def note_history(self):
        """The note history objects of the password if any."""
        if self._note_history is None:
            self._note_history = self._get_history_by_attribute('note')
        return self._note_history

    @property
    def username_history(self):
        """The note username objects of the password if any."""
        if self._username_history is None:
            self._username_history = self._get_history_by_attribute('username')
        return self._username_history

    @property
    def password_history(self):
        """The note password objects of the password if any."""
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
            value = EncryptManager.decrypt_aes256_auto(entry.get('value').encode('utf-8'),
                                                       self.encryption_key,
                                                       base64=True)
            try:
                new['value'] = value.decode('utf-8')
            except UnicodeDecodeError:
                new['value'] = str(value)
            decrypted_entries.append(new)
        return [History(*data.values()) for data in decrypted_entries]

    def get_latest_password_update_person(self):
        """The email of the last person that updated the password if any, else None."""
        try:
            return self.password_history[-1].person
        except IndexError:
            return None

    @property
    def secret_updated_datetime(self):
        return self.last_password_change_datetime


class SecureNote(Secret):
    """Models a secure note."""

    attribute_mapping = {}

    def __init__(self, lastpass_instance, data, shared_folder):
        super().__init__(lastpass_instance, data, shared_folder)
        for attribute in self.attribute_mapping.values():
            try:
                setattr(self, attribute, self._data.get(attribute))
            except AttributeError:
                # There is a conflict between a note field and one of the set attributes in the secret so the attribute
                # cannot be set but the value will be exposed by the parent secret class attribute.
                pass
        self._history = None

    @property
    def secret_updated_datetime(self):
        return self.last_modified_datetime if not hasattr(self, 'password') else self.last_password_change_datetime

    @property
    def history(self):
        """History of the secure note edits if any."""
        if self._history is None:
            url = f'{self._lastpass.host}/getNoteHist.php'
            data = {'aid': self.id,
                    'sharedfolderid': self.shared_folder.id if self.shared_folder else '',
                    'lpversion': LASTPASS_VERSION,
                    'method': 'cr',
                    'token': self._lastpass.token}
            response = self._lastpass.session.post(url, data=data)
            if not response.ok:
                response.raise_for_status()
            result = []
            for entry in response.json():
                info = {}
                for index, attribute in enumerate(['value', 'date', 'person']):
                    try:
                        info[attribute] = entry[index]
                    except IndexError:
                        info[attribute] = ''
                info['value'] = EncryptManager.decrypt_aes256_auto(info.get('value').encode('utf-8'),
                                                                   self.encryption_key,
                                                                   base64=True)
                result.append(History(**info))
            self._history = result
        return self._history


class Address(SecureNote):
    """Models an Address secure note."""

    attribute_mapping = {'Language': 'language',
                         'Title': 'title',
                         'First Name': 'first_name',
                         'Middle Name': 'middle_name',
                         'Last Name': 'last_name',
                         'Username': 'username',
                         'Gender': 'gender',
                         'Birthday': 'birthday',
                         'Company': 'company',
                         'Address 1': 'address_1',
                         'Address 2': 'address_2',
                         'Address 3': 'address_3',
                         'City / Town': 'city_town',
                         'County': 'country',
                         'State': 'state',
                         'Zip / Postal Code': 'zip_postal_code',
                         'Country': 'country',
                         'Timezone': 'timezone',
                         'Email Address': 'email_address',
                         'Phone': 'phone',
                         'Evening Phone': 'evening_phone',
                         'Mobile Phone': 'mobile_phone',
                         'Fax': 'fax',
                         'Notes': 'notes'}


class BankAccount(SecureNote):
    """Models a Bank Account secure note."""

    attribute_mapping = {'Language': 'language',
                         'Bank Name': 'bank_name',
                         'Account Type': 'account_type',
                         'Routing Number': 'routing_number',
                         'Account Number': 'accounting_number',
                         'SWIFT Code': 'swift_code',
                         'IBAN Number': 'iban_number',
                         'Pin': 'pin',
                         'Branch Address': 'branch_address',
                         'Branch Phone': 'branch_phone',
                         'Notes': 'notes'}


class CreditCard(SecureNote):
    """Models a Credit Card secure note."""

    attribute_mapping = {'Language': 'language',
                         'Name on Card': 'name_on_card',
                         'Type': 'type',
                         'Number': 'number',
                         'Security Code': 'security_code',
                         'Start Date': 'start_date',
                         'Expiration Date': 'expiration_date',
                         'Notes': 'notes'}


class Custom(SecureNote):
    """Models a Custom secure note."""

    @property
    def attribute_mapping(self):
        """Attribute mapping."""
        return self._data.get('custom_attribute_mapping', {})


class Database(SecureNote):
    """Models a Database secure note."""

    attribute_mapping = {'Language': 'language',
                         'Type': 'type',
                         'Hostname': 'hostname',
                         'Port': 'port',
                         'Database': 'database',
                         'Username': 'username',
                         'Password': 'password',
                         'SID': 'sid',
                         'Alias': 'alias',
                         'Notes': 'notes'}


class DriverLicense(SecureNote):
    """Models a Driver license secure note."""

    attribute_mapping = {'Language': 'language',
                         'Number': 'number',
                         'Expiration Date': 'expiration_date',
                         'License Class': 'license_class',
                         'Name': 'name',
                         'Address': 'address',
                         'City / Town': 'city_town',
                         'State': 'state',
                         'ZIP / Postal Code': 'zip_postal_code',
                         'Country': 'country',
                         'Date of Birth': 'date_of_birth',
                         'Sex': 'sex',
                         'Height': 'height',
                         'Notes': 'notes'}


class EmailAccount(SecureNote):
    """Models a Email Account secure note."""

    attribute_mapping = {'Language': 'language',
                         'Username': 'username',
                         'Password': 'password',
                         'Server': 'server',
                         'Port': 'port',
                         'Type': 'type',
                         'SMTP Server': 'smtp_server',
                         'SMTP Port': 'smtp_port',
                         'Notes': 'notes'}


class Generic(SecureNote):
    """Models a Generic secure note."""

    attribute_mapping = {}

    @property
    def notes(self):
        return self._data.get('notes')


class HealthInsurance(SecureNote):
    """Models a Health Insurance secure note."""

    attribute_mapping = {'Language': 'language',
                         'Company': 'company',
                         'Company Phone': 'company_phone',
                         'Policy Type': 'policy_type',
                         'Policy Number': 'policy_number',
                         'Group ID': 'insurance_group_id',
                         'Member Name': 'member_name',
                         'Member ID': 'member_id',
                         'Physician Name': 'physician_name',
                         'Physician Phone': 'physician_phone',
                         'Physician Address': 'physician_address',
                         'Co-pay': 'co_pay',
                         'Notes': 'notes'}


class InstantMessenger(SecureNote):
    """Models a Instant Messenger secure note."""

    attribute_mapping = {'Language': 'language',
                         'Type': 'type',
                         'Username': 'username',
                         'Password': 'password',
                         'Server': 'server',
                         'Port': 'port',
                         'Notes': 'notes'}


class Membership(SecureNote):
    """Models a Membership secure note."""

    attribute_mapping = {'Language': 'language',
                         'Organization': 'organization',
                         'Membership Number': 'membership_number',
                         'Member Name': 'member_name',
                         'Start Date': 'start_date',
                         'Expiration Date': 'expiration_date',
                         'Website': 'website',
                         'Telephone': 'telephone',
                         'Password': 'password',
                         'Notes': 'notes'}


class Passport(SecureNote):
    """Models a Passport secure note."""

    attribute_mapping = {'Language': 'language',
                         'Type': 'type',
                         'Name': 'name',
                         'Country': 'country',
                         'Number': 'number',
                         'Sex': 'sex',
                         'Nationality': 'nationality',
                         'Issuing Authority': 'issuing_authority',
                         'Date of Birth': 'date_of_birth',
                         'Issued Date': 'issued_date',
                         'Expiration Date': 'expiration_date',
                         'Notes': 'notes'}


class SshKey(SecureNote):
    """Models a SshKey secure note."""

    attribute_mapping = {'Language': 'language',
                         'Bit Strength': 'bit_strength',
                         'Format': 'format',
                         'Passphrase': 'passphrase',
                         'Private Key': 'private_key',
                         'Public Key': 'public_key',
                         'Hostname': 'hostname',
                         'Date': 'date',
                         'Notes': 'notes'}


class Server(SecureNote):
    """Models a Server secure note."""

    attribute_mapping = {'Language': 'language',
                         'Hostname': 'hostname',
                         'Username': 'username',
                         'Password': 'password',
                         'Notes': 'notes'}


class SocialSecurity(SecureNote):
    """Models a SocialSecurity secure note."""

    attribute_mapping = {'Language': 'language',
                         'Name': 'name',
                         'Number': 'number',
                         'Notes': 'notes'}


class SoftwareLicense(SecureNote):
    """Models a SoftwareLicense secure note."""

    attribute_mapping = {'Language': 'language',
                         'License Key': 'license_key',
                         'Licensee': 'licensee',
                         'Version': 'version',
                         'Publisher': 'publisher',
                         'Support Email': 'support_email',
                         'Website': 'website',
                         'Price': 'price',
                         'Purchase Date': 'purchase_date',
                         'Order Number': 'order_number',
                         'Number of Licenses': 'number_of_licenses',
                         'Order Total': 'order_total',
                         'Notes': 'notes'}


class WifiPassword(SecureNote):
    """Models a WifiPassword secure note."""

    attribute_mapping = {'Language': 'language',
                         'SSID': 'ssid',
                         'Password': 'password',
                         'Connection Type': 'connection_type',
                         'Connection Mode': 'connection_mode',
                         'Authentication': 'authentication',
                         'Encryption': 'encryption',
                         'Use 802.1X': 'use_8021x',
                         'FIPS Mode': 'fips_mode',
                         'Key Type': 'key_type',
                         'Protected': 'protected',
                         'Key Index': 'key_index',
                         'Notes': 'notes'}


SECRET_NOTE_CLASS_MAPPING = {'Address': Address,
                             'Bank Account': BankAccount,
                             'Credit Card': CreditCard,
                             'Custom': Custom,
                             'Database': Database,
                             "Driver's License": DriverLicense,
                             'Email Account': EmailAccount,
                             'Generic': Generic,
                             'Health Insurance': HealthInsurance,
                             'Instant Messenger': InstantMessenger,
                             'Membership': Membership,
                             'Passport': Passport,
                             'SSH Key': SshKey,
                             'Server': Server,
                             'Social Security': SocialSecurity,
                             'Software License': SoftwareLicense,
                             'Wi-Fi Password': WifiPassword
                             }

SECURE_NOTE_TYPES = [obj.__name__ for obj in SECRET_NOTE_CLASS_MAPPING.values()]


class Attachment:
    """Models an attachment of a secret."""

    def __init__(self, lastpass_instance, data):
        self._lastpass_instance = lastpass_instance
        self._data = data
        self._filename = None
        self._decryption_key_ = None
        self._content = None

    @property
    def id(self):
        """ID of the attachment."""
        return self._data.get('id')

    @property
    def parent_id(self):
        """ID of the parent secret of the attachment."""
        return self._data.get('parent_id')

    @property
    def mimetype(self):
        """The mimetype of the attachment."""
        return self._data.get('filetype')

    @property
    def uuid(self):
        """The uuid of the attachment."""
        return self._data.get('uuid')

    @property
    def _decryption_key(self):
        if self._decryption_key_ is None:
            self._decryption_key_ = EncryptManager.decode_hex(self._data.get('decryption_key'))
        return self._decryption_key_

    @property
    def filename(self):
        """The filename of the attachment."""
        if self._filename is None:
            self._filename = EncryptManager.decrypt_aes256_auto(self._data.get('encrypted_filename').encode('utf-8'),
                                                                self._decryption_key,
                                                                base64=True).decode('utf-8')
        return self._filename

    @property
    def content(self):
        """The content of the attachment."""
        if self._content is None:
            url = f'{self._lastpass_instance.host}/getattach.php'
            data = {'getattach': self.uuid}
            response = self._lastpass_instance.session.post(url, data=data)
            if not response.ok:
                response.raise_for_status()
            base64_encoded = EncryptManager.decrypt_aes256_auto(response.content, self._decryption_key, base64=True)
            self._content = base64.b64decode(base64_encoded).decode('utf-8')
        return self._content

    def save(self, path='.'):
        """Saves the attachment on a given path, current working directory if not provided.

        Args:
            path: The path to save the attachment to, defaults to current working directory.

        Returns:
            None.

        """
        with open(Path(path, self.filename), 'w', encoding='utf8') as ofile:
            ofile.write(self.content)
