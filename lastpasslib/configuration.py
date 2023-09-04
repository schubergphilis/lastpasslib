#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: configuration.py
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
Main code for configuration.

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

LASTPASS_VERSION = '4.108.1'


class Configurations:
    default = {
        'aid': '0',
        'auto': '1',
        'ajax': '1',
        'extjs': '1',
        'localupdate': '1',
        'method': 'cr',
        'requestsrc': 'cr',
        'source': 'vault',
    }
    secret_payload = {
        **default,
        'folder': 'none',
        'urid': '0',
    }
    secure_note_payload = {
        **default,
        'notetype': 'Generic',
        'password': '',
        'template': '',
        'u': '',
        'url': '',
        'username': '',
        'totp': '',
    }
    move_secrets_payload = {
        'cmd': 'uploadaccounts',
        'hasplugin': '4.119.0',
        'lpversion': '4.119.0',
        'pwprotect0': '0',
        'realm0': '',
        'requestsrc': 'cr',
        'sessonly': '0',
        'type0': 'cr',
    }
