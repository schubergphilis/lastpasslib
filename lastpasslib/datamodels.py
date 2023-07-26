# !/usr/bin/env python
# -*- coding: utf-8 -*-
# File: datamodels.py
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
Main code for datamodels.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

from dataclasses import dataclass, field

from dateutil.parser import parse

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
class Event:
    """Models data of an event on the server."""

    _name1: str
    _name2: str
    _name3: str
    _name4: str
    _name5: str
    name: str
    group: str
    date: str
    ip: str
    reverse: str
    action: str
    ulid: str
    share_id: str

    @property
    def datetime(self):
        """Datetime object of the date."""
        return parse(self.date)

    @property
    def name_alternative(self):
        """The alternative name of the event. Concatenating attributes name_1 to name_5."""
        return ''.join([self._name1, self._name2, self._name3, self._name4, self._name5])

    def __str__(self):
        attributes = ['name', 'name_alternative', 'group', 'date', 'ip', 'reverse', 'action']
        values = "\n".join([f'{attribute}: {getattr(self, attribute)}' for attribute in attributes])
        return f'{values}\n\n'


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
class Chunk:
    """Models data of an encrypted chunk of the vault blob."""

    id: bytes
    payload_size: bytes
    payload: bytes


@dataclass
class SharedFolder:
    """Models data of a shared folder."""

    id: str
    read_only: str
    give: str
    name: str
    deleted: str
    last_modified: str
    association: str
    can_administer: str
    invisible: str
    created: str
    cgid: str
    download: str
    outside_enterprise: str
    cid: str
    share_data: str = ''
    sharer: str = ''
    shared_name: str = ''

    @property
    def last_modified_datetime(self):
        """Datetime object of the last modified date."""
        return parse(self.last_modified)

    def __str__(self):
        attributes = ['id', 'name', 'read_only', 'deleted', 'created', 'last_modified', 'sharer']
        values = "\n".join([f'{attribute}: {getattr(self, attribute)}' for attribute in attributes])
        return f'{values}\n\n'


@dataclass
class NeverUrl:
    """Models data of a never url."""

    id: int
    url: str


@dataclass
class EquivalentDomain:
    """Models data of an equivalent domain."""

    id: int
    url: str


@dataclass
class UrlRule:
    """Models data of a url rule."""

    url: str
    exact_host: bool
    exact_port: bool
    case_insensitive: bool


@dataclass
class CompanyUser:
    """Models data of a company user."""

    email: str
    img: str
    name: str
    type: str
    uid: str


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


@dataclass
class Folder:
    name: str
    path: tuple
    parent: 'Folder' = None
    folders: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    is_personal: bool = False

    @property
    def full_path(self):
        return '\\'.join(self.path)

    @property
    def is_in_root(self):
        return len(self.path) == 1

    def add_secret(self, secret):
        self.secrets.append(secret)

    def add_secrets(self, secrets):
        self.secrets.extend(secrets)

    def add_folder(self, folder):
        self.folders.append(folder)

    def add_folders(self, folders):
        self.folders.extend(folders)


@dataclass
class DecryptedVault:
    encrypted_username: str
    attachments: list
    never_urls: list
    equivalent_domains: list
    url_rules: list
    secrets: list
    folder_entries: list
