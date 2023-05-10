#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: test_lastpasslib.py
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
test_lastpasslib
----------------------------------
Tests for `lastpasslib` module.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

from betamax.fixtures import unittest
from lastpasslib.encryption import EncryptManager

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''08-02-2023'''
__copyright__ = '''Copyright 2023, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class TestLastpasslib(unittest.BetamaxTestCase):

    def setUp(self):
        """
        Test set up

        This is where you can setup things that you use throughout the tests. This method is called before every test.
        """
        pass

    def tearDown(self):
        """
        Test tear down

        This is where you should tear down what you've setup in setUp before. This method is called after every test.
        """
        pass


class TestEncryption(unittest.BetamaxTestCase):

    def setUp(self):
        """
        Test set up

        This is where you can setup things that you use throughout the tests. This method is called before every test.
            """
        self.clear_text = 'this is a test text to encode.'
        self.hex_encoded = b'7468697320697320612074657374207465787420746f20656e636f64652e'

    def tearDown(self):
        """
        Test tear down

        This is where you should tear down what you've setup in setUp before. This method is called after every test.
        """
        pass

    def test_encode_hex(self):
        self.assertEqual(self.hex_encoded, EncryptManager.encode_hex(self.clear_text.encode('utf-8')))

    def test_decode_hex(self):
        self.assertEqual(self.clear_text.encode('utf-8'), EncryptManager.decode_hex(self.hex_encoded))

    def test_encode_decode_hex(self):
        self.assertEqual(self.clear_text.encode('utf-8'),
                         EncryptManager.decode_hex(EncryptManager.encode_hex(self.clear_text.encode('utf-8'))))

    def test_decode_encode_hex(self):
        self.assertEqual(self.hex_encoded, EncryptManager.encode_hex(EncryptManager.decode_hex(self.hex_encoded)))
