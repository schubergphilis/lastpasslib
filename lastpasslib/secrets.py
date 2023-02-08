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
import logging
from copy import copy
from datetime import datetime
from pathlib import Path

from .configuration import LASTPASS_VERSION
from .datamodels import History, ShareAction
from .encryption import EncryptManager

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


class Secret:
    """Models the secret and exposes the main attributes that are shared across Passwords and Secure Notes."""

    def __init__(self, lastpass_instance, data, shared_folder=None):
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
            if not response.ok:
                response.raise_for_status()
            sent = response.json().get('sent')
            if not sent:
                return []
            action_attributes = ['companyUserName', 'date', 'email', 'give', 'sharedate', 'state', 'uid']
            actions = sent.get(self.id)
            self._shared_to_people = [ShareAction(*[action.get(attribute) for attribute in action_attributes])
                                      for action in actions]
        return self._shared_to_people


class Password(Secret):

    def __init__(self, lastpass_instance, data, shared_folder=None):
        super().__init__(lastpass_instance, data, shared_folder)
        self._note_history = None
        self._username_history = None
        self._password_history = None

    @property
    def action(self):
        return self._data.get('action')

    @property
    def auto_login(self):
        return self._data.get('auto_login')

    @property
    def is_generated_password(self):
        return self._data.get('generated_password')

    @property
    def mfa_seed(self):
        return self._data.get('mfa_seed')

    @property
    def never_autofill(self):
        return self._data.get('never_autofill')

    @property
    def notes(self):
        return self._data.get('notes')

    @property
    def password(self):
        return self._data.get('password')

    @property
    def url(self):
        return self._data.get('url')

    @property
    def username(self):
        return self._data.get('username')

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
        try:
            return self.password_history[-1].person
        except IndexError:
            return None


class SecureNote(Secret):
    attribute_mapping = {}

    def __init__(self, lastpass_instance, data, shared_folder):
        super().__init__(lastpass_instance, data, shared_folder)
        for attribute in self.attribute_mapping.values():
            try:
                setattr(self, attribute, self._data.get(attribute))
            except AttributeError:
                LOGGER.error(f'Trying to over write attribute {attribute} for class {self.__class__.__name__}')
        self._history = None

    @property
    def history(self):
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
    attribute_mapping = {'Language': 'language',
                         'Name on Card': 'name_on_card',
                         'Type': 'type',
                         'Number': 'number',
                         'Security Code': 'security_code',
                         'Start Date': 'start_date',
                         'Expiration Date': 'expiration_date',
                         'Notes': 'notes'}


class Custom(SecureNote):

    @property
    def attribute_mapping(self):
        return self._data.get('custom_attribute_mapping', {})


class Database(SecureNote):
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
    attribute_mapping = {}

    @property
    def notes(self):
        return self._data.get('notes')


class HealthInsurance(SecureNote):
    attribute_mapping = {'Language': 'language',
                         'Company': 'company',
                         'Company Phone': 'company_phone',
                         'Policy Type': 'policy_type',
                         'Policy Number': 'policy_number',
                         'Group ID': 'group_id',
                         'Member Name': 'member_name',
                         'Member ID': 'member_id',
                         'Physician Name': 'physician_name',
                         'Physician Phone': 'physician_phone',
                         'Physician Address': 'physician_address',
                         'Co-pay': 'co_pay',
                         'Notes': 'notes'}


class InstantMessenger(SecureNote):
    attribute_mapping = {'Language': 'language',
                         'Type': 'type',
                         'Username': 'username',
                         'Password': 'password',
                         'Server': 'server',
                         'Port': 'port',
                         'Notes': 'notes'}


class Membership(SecureNote):
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
    attribute_mapping = {'Language': 'language',
                         'Hostname': 'hostname',
                         'Username': 'username',
                         'Password': 'password',
                         'Notes': 'notes'}


class SocialSecurity(SecureNote):
    attribute_mapping = {'Language': 'language',
                         'Name': 'name',
                         'Number': 'number',
                         'Notes': 'notes'}


class SoftwareLicense(SecureNote):
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


class Attachment:

    def __init__(self, lastpass_instance, data):
        self._lastpass_instance = lastpass_instance
        self._data = data
        self._filename = None
        self._decryption_key_ = None
        self._content = None

    @property
    def id(self):
        return self._data.get('id')

    @property
    def mimetype(self):
        return self._data.get('filetype')

    @property
    def uuid(self):
        return self._data.get('uuid')

    @property
    def _decryption_key(self):
        if self._decryption_key_ is None:
            self._decryption_key_ = EncryptManager.decode_hex(self._data.get('decryption_key'))
        return self._decryption_key_

    @property
    def filename(self):
        if self._filename is None:
            self._filename = EncryptManager.decrypt_aes256_auto(self._data.get('encrypted_filename').encode('utf-8'),
                                                                self._decryption_key,
                                                                base64=True).decode('utf-8')
        return self._filename

    @property
    def content(self):
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
        with open(Path(path, self.filename), 'w', encoding='utf8') as ofile:
            ofile.write(self.content)
