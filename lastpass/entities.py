import struct
from base64 import b64decode
from dataclasses import dataclass
from io import BytesIO

from dateutil.parser import parse

from .lastpassexceptions import ServerError


@dataclass
class History:
    date: str
    value: str
    person: str

    @property
    def datetime(self):
        return parse(self.date)


@dataclass
class Chunk:
    id: bytes
    payload: bytes


@dataclass
class SharedFolder:
    id: str
    name: str


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


class ChunkStream:
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
            if not ChunkStream.is_complete(chunks):
                raise ServerError('Blob is truncated')
            self._chunks = chunks
        return self._chunks


class Account(object):
    def __init__(self, lastpass_instance, id, name, username, password, url, group, notes=None, shared_folder=None):
        self._lastpass = lastpass_instance
        self.id = id.decode('utf-8')
        self.name = name.decode('utf-8')
        self.username = username.decode('utf-8')
        self.password = password.decode('utf-8')
        self.url = url.decode('utf-8')
        self.group = group.decode('utf-8')
        self.notes = notes.decode('utf-8')
        self.shared_folder = shared_folder
        self._history = None

    @property
    def history(self):
        if self._history is None:
            url = f'{self._lastpass.host}/lmiapi/accounts/{self.id}/history/note'
            params = {'sharedFolderId': self.shared_folder.id} if self.shared_folder else {}
            response = self._lastpass._session.get(url, params=params)
            if not response.ok:
                response.raise_for_status()
            self._history = [History(*data.values()) for data in response.json().get('history')]
        return self._history

    def get_latest_update_person(self):
        try:
            return self.history[-1].person
        except IndexError:
            return None
