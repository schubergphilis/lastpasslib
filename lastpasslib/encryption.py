#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: encryption.py
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
Main code for encryption.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

import codecs
import os
import re
import struct
from base64 import b64decode, b64encode
from io import BytesIO

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import number
from binascii import Error as BinasciiError

from lastpasslib.datamodels import Chunk
from lastpasslib.lastpasslibexceptions import ServerError
import urllib

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''08-02-2023'''
__copyright__ = '''Copyright 2023, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos", "Yorick Hoorneman"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".


class Stream:
    """Models a stream of encrypted data and implements appropriate data retrieval capabilities.

    # An item in an itemized chunk is made up of the
    # big endian size and the payload of that size.
    #
    # Example:
    #   0000: 4
    #   0004: 0xDE 0xAD 0xBE 0xEF
    #   0008: --- Next item ---
    """

    def __init__(self, data):
        self._stream = BytesIO(data)
        self.length = self._get_length()

    def _get_length(self):
        current_pos = self._stream.tell()
        # go to the end of the stream
        self._stream.seek(0, 2)
        # get the actual length
        length = self._stream.tell()
        # reset to the beginning
        self._stream.seek(current_pos, 0)
        return length

    @property
    def position(self):
        """The current position of the stream."""
        return self._stream.tell()

    def read_byte_size(self, size):
        """Reads the next size provided bytes from a stream and returns it as bytes.

        Args:
            size: An integer for the size to retrieve.

        Returns:
            bytes: The bytes for the provided size.

        """
        return self._stream.read(size)

    def get_payload_by_size(self, payload_size):
        """Reads a payload from a stream by the provided size and returns it as bytes.

        Args:
            payload_size (bytes): The payload size to retrieve.

        Returns:
            bytes: The payload.

        """
        return self._stream.read(struct.unpack('>I', payload_size)[0])

    def skip_item(self, times=1):
        """Skips an item in a stream as many times as provided.

        Args:
            times (int): The times to skip the payload.

        Returns:
            None

        """
        for _ in range(times):
            self.get_payload_by_size(self.read_byte_size(4))


class Blob:
    """Models the encrypted blob and implements functionality to traverse it and split it into encrypted chunks."""

    def __init__(self, blob):
        self._data = b64decode(blob)
        self._chunks = []

    @staticmethod
    def is_complete(chunks):
        """If the blob is complete.

        The last chunk of the encrypted blob should be an entry of "ENDM" with payload of "OK"

        Args:
            chunks: The collection of chunks of the blob.

        Returns:
            True is the blob is complete, False otherwise.

        """
        if not chunks:
            return False
        conditions = [chunks[-1].id == b'ENDM',
                      chunks[-1].payload == b'OK']
        return all(conditions)

    @property
    def chunks(self):
        """The chunks of the blob."""
        # LastPass blob chunk is made up of 4-byte ID,
        # big endian 4-byte size and payload of that size.
        #
        # Example:
        #   0000: "IDID"
        #   0004: 4
        #   0008: 0xDE 0xAD 0xBE 0xEF
        #   000C: --- Next chunk ---
        if not self._chunks:
            chunks = []
            stream = Stream(self._data)
            while stream.position < stream.length:
                chunk_id = stream.read_byte_size(4)
                payload_size = stream.read_byte_size(4)
                payload = stream.get_payload_by_size(payload_size)
                chunks.append(Chunk(chunk_id, payload_size, payload))
            if not Blob.is_complete(chunks):
                raise ServerError('Blob is truncated')
            self._chunks = chunks
        return self._chunks


class EncryptManager:
    """Handles the decryption and decoding for all appropriate methods."""

    @staticmethod
    def create_random_iv(byte_size: int = 16) -> bytes:
        """Creates an Initialization Vector (IV) byte string for a given length.

        Args:
            byte_size (int): length of the byte string. Defaults to 16.

        Returns:
            bytes: Byte string

        """
        return os.urandom(byte_size)

    @staticmethod
    def decode_hex(data):
        """Decodes a hex encoded string into raw bytes.

        Args:
            data: The data to decode

        Returns:
            The decoded data on success.

        Raises:
            TypeError if the decoding is not possible.

        """
        try:
            return codecs.decode(data, 'hex_codec')
        except BinasciiError:
            raise TypeError(f'Data :{data} could not be decoded by the "hex_codec".') from None

    @staticmethod
    def encode_hex(data):
        """Encodes a raw bytes string to a hex encoded string.

        Args:
            data: The data to encode

        Returns:
            The encoded data on success.

        Raises:
            TypeError if the encoding is not possible.

        """
        try:
            return codecs.encode(data, 'hex_codec')
        except BinasciiError:
            raise TypeError(f'Data :{data} could not be encoded by the "hex_codec".') from None

    @staticmethod
    def decrypt_rsa_key(payload, encryption_key):
        """Parse PRIK chunk which contains a private RSA key and decrypt it.

        Args:
            payload: The payload that holds the encrypted rsa key.
            encryption_key: The key to use to decrypt the payload.

        Returns:
            A decrypted RSA key.

        """
        decrypted = EncryptManager.decrypt_aes256_cbc(encryption_key[:16],
                                                      EncryptManager.decode_hex(payload),
                                                      encryption_key)
        regex_match = br'^LastPassPrivateKey<(?P<hex_key>.*)>LastPassPrivateKey$'
        hex_key = re.match(regex_match, decrypted).group('hex_key')
        rsa_key = RSA.importKey(EncryptManager.decode_hex(hex_key))
        rsa_key.dmp1 = rsa_key.d % (rsa_key.p - 1)
        rsa_key.dmq1 = rsa_key.d % (rsa_key.q - 1)
        rsa_key.iqmp = number.inverse(rsa_key.q, rsa_key.p)
        return rsa_key

    @staticmethod
    def decrypt_aes256_auto(data, encryption_key, base64=False):
        """Guesses AES cipher (ECB or CBD) from the length of the plain data.

        Args:
            data: The data to decrypt.
            encryption_key: The key to use to decrypt the data.
            base64: Flag of whether the payload is base64 encoded or plain text encrypted.

        Returns:
            The decrypted data of the payload.

        Raises:
            TypeError: The data is not of type bytes

        """
        if not isinstance(data, bytes):
            raise TypeError('Data should be bytes.')
        length = len(data)
        if not length:
            return b''
        # trying to identify automatically whether provided data are base64 encode.
        # had one collision with plain data having | as 26 character so that is not robust enough...
        # base64_check = data[0], data[25] == (b'!'[0], b'|'[0])
        # if base64 we only check for the first byte
        conditions = [data[0] == b'!'[0]]
        if not base64:
            # in plain text we also check the sizes
            conditions.extend([length % 16 == 1, length > 32])
        if all(conditions):
            # in cbc plain iv is data[1:17] and data is data[17:]
            # but in base64 iv is b64decode(data[1:25]) and data is b64decode(data[26:])
            # b64encoded cbc first character is ! {1-24}=iv then there is a | {rest data}
            cipher = 'cbc'
            arguments = [data[1:17], data[17:]] if not base64 else [b64decode(data[1:25]), b64decode(data[26:])]
        else:
            cipher = 'ecb'
            arguments = [data] if not base64 else [b64decode(data)]
        arguments.append(encryption_key)
        return getattr(EncryptManager, f'decrypt_aes256_{cipher}')(*arguments)

    @staticmethod
    def decrypt_aes256_cbc(iv: bytes, data: bytes, encryption_key: bytes) -> bytes:
        """Decrypt AES-256 bytes with CBC.

        Args:
            iv (bytes): The initialization vector
            data (bytes): The data to decrypt
            encryption_key (bytes): The key used to decrypt

        Returns:
            bytes: Byte string

        """
        decrypted_data = AES.new(encryption_key, AES.MODE_CBC, iv).decrypt(data)
        return EncryptManager._unpad_pkcs5_data(decrypted_data)

    @staticmethod
    def encrypt_aes256_cbc(iv: bytes, data: bytes, encryption_key: bytes) -> bytes:
        """Encrypt AES-256 bytes with CBC.

        Args:
            iv (bytes): The initialization vector
            data (bytes): The data to encrypt
            encryption_key (bytes): The key used to encrypt

        Returns:
            bytes: Byte string of hex

        """
        padded_data = EncryptManager._pad_pkcs5_data(data)
        return AES.new(encryption_key, AES.MODE_CBC, iv).encrypt(padded_data)

    @staticmethod
    def decrypt_aes256_ecb(data: bytes, encryption_key: bytes) -> bytes:
        """Decrypt AES-256 bytes with ECB.

        Args:
            data (bytes): The data to decrypt
            encryption_key (bytes): The key used to decrypt

        Returns:
            bytes: Byte string

        """
        decrypted_data = AES.new(encryption_key, AES.MODE_ECB).decrypt(data)
        return EncryptManager._unpad_pkcs5_data(decrypted_data)

    @staticmethod
    def _unpad_pkcs5_data(data: bytes) -> bytes:
        r"""Removes extra bits or bytes after it is decrypted.

        Source used http://passingcuriosity.com/2009/aes-encryption-in-python-with-m2crypto/.

        Example:
            data = 'This is a test string'
            block_size = 8
            output = 'This is a test string\x03\x03\x03'

            block_size = 16
            output = 'This is a test string\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'

        Args:
            data (bytes): byte string with padding

        Returns:
            bytes: Byte string

        """
        return data[0:-ord(data[-1:])]

    @staticmethod
    def _pad_pkcs5_data(data: bytes, block_size: int = 16) -> bytes:
        r"""Add extra bits or bytes of padding to plaintext before it is encrypted.

        Source used http://passingcuriosity.com/2009/aes-encryption-in-python-with-m2crypto/.

        Example:
            data = 'This is a test string'
            block_size = 8
            output = b'This is a test string\x03\x03\x03'

            block_size = 16
            output = b'This is a test string\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'

        Args:
            data (bytes): byte string
            block_size (int): block size. Defaults to 16.

        Returns:
            bytes: data provided with padding appended

        """
        padding = (block_size - len(data) % block_size) * chr(block_size - len(data) % block_size)
        return data + padding.encode()

    @staticmethod
    def encrypt_and_encode_payload(encryption_key: str, payload: str) -> str:
        """aes256_cbc encrypting and encoding a payload.

        Args:
            encryption_key (str): _description_
            payload (str): _description_

        Returns:
            str: _description_

        """
        if not all([payload and encryption_key]):
            return ''
        iv = EncryptManager.create_random_iv()
        encrypted_attribute = EncryptManager.encrypt_aes256_cbc(iv, payload.encode(), encryption_key)
        url_encoded_data = urllib.parse.quote(f'{b64encode(iv).decode("utf-8")}'
                                              f'|{b64encode(encrypted_attribute).decode("utf-8")}', safe='')
        return f'!{url_encoded_data}'
