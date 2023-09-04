#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: lastpasslibexceptions.py
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
Custom exception code for lastpasslib.

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


class ApiLimitReached(Exception):
    """Server responded with a 429 status."""


class InvalidMfa(Exception):
    """The mfa token provided is invalid."""


class InvalidPassword(Exception):
    """The password provided is invalid."""


class InvalidYubiKey(Exception):
    """The yubikey token provided is invalid."""


class MfaRequired(Exception):
    """A mfa token is required but not provided."""


class ServerError(Exception):
    """Server responded with some error."""


class UnknownUsername(Exception):
    """The username provided is not known to the server."""


class UnexpectedResponse(Exception):
    """The response provided does not follow the expected format."""


class InvalidSecretType(Exception):
    """The secret type provided is not a valid one."""


class MultipleInstances(Exception):
    """There is more than one item returned."""


class UnknownIP(Exception):
    """The ip of the connection is not know to the service."""


class MobileDevicesRestricted(Exception):
    """Mobile devices are restricted on the Account settings of lastpass."""


class MissingResult(Exception):
    """Server response does not contain a result."""


class UnknownFolder(Exception):
    """No folder is found."""


class UnknownAccountID(Exception):
    """No Account ID is found."""


class RemoteCommandInvalidResult(Exception):
    """The result of the Remote Command is not valid."""


class UnknownSecret(Exception):
    """No secret is found."""
