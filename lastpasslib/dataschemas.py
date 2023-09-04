# !/usr/bin/env python
# -*- coding: utf-8 -*-
# File: dataschemas.py
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
Main code for dataschemas.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''08-02-2023'''
__copyright__ = '''Copyright 2023, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos", "Yorick Hoorneman"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class SecretSchema:

    def __init__(self):
        self.attributes = ['id', 'name', 'group', 'url', 'notes', 'is_favorite', 'shared_from_id', 'username',
                           'password', 'is_password_protected', 'is_generated_password', 'is_secure_note',
                           'last_touch_timestamp', 'auto_login_set', 'never_autofill', 'realm_data', 'fi_id',
                           'custom_js', 'submit_id', 'captcha_id', 'ur_id', 'is_basic_auth', 'method', 'action',
                           'group_id', 'is_deleted', 'attachment_encryption_key', 'has_attachment',
                           'is_individual_share', 'note_type', 'no_alert', 'last_modified_gmt', 'has_been_shared',
                           'last_password_change_gmt', 'created_gmt', 'vulnerable', 'auto_change_password_supported',
                           'is_breached', 'custom_note_definition_json', 'mfa_seed', 'undocumented_attribute_1',
                           'undocumented_attribute_2', 'undocumented_attribute_3']
        self.plain_encrypted = ['name', 'group', 'notes', 'username', 'password', 'mfa_seed',
                                'undocumented_attribute_1']
        self.base_64_encrypted = ['attachment_encryption_key']
        self.hex_decoded = ['url']
        self.boolean_values = ['is_favorite', 'is_password_protected', 'is_generated_password', 'is_secure_note',
                               'auto_login_set', 'never_autofill', 'is_basic_auth', 'is_deleted', 'is_individual_share',
                               'has_been_shared', 'auto_change_password_supported', 'is_breached']
        self.not_decodable_values = ['realm_data']
        self.decoded_attributes = [value for value in self.attributes if value not in self.not_decodable_values]


class SharedFolderSchema:

    def __init__(self):
        self.attributes = ['id', 'encrypted_key', 'encrypted_name', 'unknown_flag_1', 'unknown_flag_2', 'key']
        self.plain_encrypted = []
        self.hex_decoded = ['encrypted_key']
        self.boolean_values = []
        self.not_decodable_values = ['encrypted_key', 'encrypted_name', 'unknown_flag_1', 'unknown_flag_2', 'key']
        self.decoded_attributes = [value for value in self.attributes if value not in self.not_decodable_values]


class AttachmentSchema:

    def __init__(self):
        self.attributes = ['id', 'parent_id', 'filetype', 'uuid', 'size', 'encrypted_filename']
        self.plain_encrypted = []
        self.hex_decoded = []
        self.boolean_values = []
        self.not_decodable_values = []
        self.decoded_attributes = [value for value in self.attributes if value not in self.not_decodable_values]
