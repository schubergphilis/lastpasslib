import codecs
import struct
from base64 import b64decode
from io import BytesIO

import binascii
from Crypto.Cipher import AES

from .datamodels import Chunk
from .lastpassexceptions import ServerError


class Stream:

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
        return self._stream.tell()

    def next_by_size(self, size):
        """Reads the next size provided bytes from a stream and returns it as a string of bytes."""
        return self._stream.read(size)

    def next_item(self):
        """Reads an item from a stream and returns it as a string of bytes."""
        # An item in an itemized chunk is made up of the
        # big endian size and the payload of that size.
        #
        # Example:
        #   0000: 4
        #   0004: 0xDE 0xAD 0xBE 0xEF
        #   0008: --- Next item ---
        return self._stream.read(struct.unpack('>I', self._stream.read(4))[0])

    def skip_item(self, times=1):
        """Skips an item in a stream."""
        for _ in range(times):
            self.next_item()


class Blob:
    def __init__(self, blob):
        self._data = b64decode(blob)
        self._chunks = []

    @staticmethod
    def is_complete(chunks):
        if not chunks:
            return False
        conditions = [chunks[-1].id == b'ENDM',
                      chunks[-1].payload == b'OK']
        return all(conditions)

    @property
    def chunks(self):
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
                chunk_id = stream.next_by_size(4)
                payload = stream.next_item()
                chunks.append(Chunk(chunk_id, payload))
            if not Blob.is_complete(chunks):
                raise ServerError('Blob is truncated')
            self._chunks = chunks
        return self._chunks


class Decoder:

    @staticmethod
    def decode_hex(data):
        """Decodes a hex encoded string into raw bytes."""
        try:
            return codecs.decode(data, 'hex_codec')
        except binascii.Error:
            raise TypeError()

    @staticmethod
    def decode_aes256_auto(data, encryption_key, base64=False):
        """Guesses AES cipher (ECB or CBD) from the length of the plain data."""
        if not isinstance(data, bytes):
            raise TypeError('Data should be bytes.')
        length = len(data)
        if not length:
            return b''
        # if base64 we only check for the first byte
        conditions = [data[0] == b'!'[0]]
        if not base64:
            # in plain text we also check the sizes
            conditions.extend([length % 16 == 1, length > 32])
        if all(conditions):
            # in cbc plain iv is data[1:17] and data is data[17:]
            # but in base64 iv is b64decode(data[1:25]) and data is b64decode(data[26:])
            cipher = 'cbc'
            arguments = [data[1:17], data[17:]] if not base64 else [b64decode(data[1:25]), b64decode(data[26:])]
        else:
            cipher = 'ecb'
            arguments = [data] if not base64 else [b64decode(data)]
        arguments.append(encryption_key)
        return getattr(Decoder, f'decode_aes256_{cipher}')(*arguments)

    @staticmethod
    def decode_aes256_cbc(iv, data, encryption_key):
        """
        Decrypt AES-256 bytes with CBC.
        """
        decrypted_data = AES.new(encryption_key, AES.MODE_CBC, iv).decrypt(data)
        return Decoder._unpad_decrypted_data(decrypted_data)

    @staticmethod
    def decode_aes256_ecb(data, encryption_key):
        """
        Decrypt AES-256 bytes with CBC.
        """
        decrypted_data = AES.new(encryption_key, AES.MODE_ECB).decrypt(data)
        return Decoder._unpad_decrypted_data(decrypted_data)

    @staticmethod
    def _unpad_decrypted_data(decrypted_data):
        # http://passingcuriosity.com/2009/aes-encryption-in-python-with-m2crypto/
        return decrypted_data[0:-ord(decrypted_data[-1:])]