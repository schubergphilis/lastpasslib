import logging
from copy import copy
from datetime import datetime

from .datamodels import History
from .encryption import EncryptManager

LOGGER_BASENAME = 'secrets'
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


class Secret:
    def __init__(self, lastpass_instance, data, shared_folder=None):
        self._lastpass = lastpass_instance
        self._data = data
        self._shared_folder = shared_folder

    @property
    def secret_type(self):
        return self.__class__.__name__.lower()

    @property
    def attachment_encryption_key(self):
        return self._data.get('attachment_encryption_key')

    @property
    def created_datetime(self):
        return datetime.fromtimestamp(int(self._data.get('created_gmt')))

    @property
    def is_deleted(self):
        return self._data.get('deleted')

    @property
    def is_favorite(self):
        return self._data.get('is_favorite')

    @property
    def group(self):
        return self._data.get('group')

    @property
    def has_attachment(self):
        return bool(self._data.get('has_attachment'))

    @property
    def has_been_shared(self):
        return self._data.get('has_been_shared')

    @property
    def id(self):
        return self._data.get('id')

    @property
    def is_individual_share(self):
        return self._data.get('is_individual_share')

    @property
    def is_secure_note(self):
        return self._data.get('is_secure_note')

    @property
    def last_modified_datetime(self):
        return datetime.fromtimestamp(int(self._data.get('last_modified_gmt')))

    @property
    def last_password_change_datetime(self):
        return datetime.fromtimestamp(int(self._data.get('last_password_change_gmt')))

    @property
    def last_touch_datetime(self):
        return datetime.fromtimestamp(int(self._data.get('last_touch_timestamp')))

    @property
    def name(self):
        return self._data.get('name')

    @property
    def shared_folder(self):
        return self._shared_folder

    @property
    def is_password_protected(self):
        return self._data.get('is_password_protected')

    @property
    def shared_from_id(self):
        return self._data.get('shared_from_id')


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


class SecureNote(Secret):
    attribute_mapping = {}

    def __init__(self, lastpass_instance, data, shared_folder):
        super().__init__(lastpass_instance, data, shared_folder)
        for attribute in self.attribute_mapping.values():
            try:
                setattr(self, attribute, self._data.get(attribute))
            except AttributeError:
                LOGGER.error(f'Trying to over write attribute {attribute} for class {self.__class__.__name__}')


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
    attribute_mapping = {}


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
                         'Password': 'passwordpassword',
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
