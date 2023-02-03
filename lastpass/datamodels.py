from dataclasses import dataclass

from dateutil.parser import parse


@dataclass
class Event:
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
        return parse(self.date)

    @property
    def name_alternative(self):
        return ''.join([self._name1, self._name2, self._name3, self._name4, self._name5])

    def __repr__(self):
        attributes = ['name', 'name_alternative', 'group', 'date', 'ip', 'reverse', 'action']
        values = "\n".join([f'{attribute}: {getattr(self, attribute)}' for attribute in attributes])
        return f'{values}\n\n'


@dataclass
class History:
    date: str
    value: str
    person: str

    @property
    def datetime(self):
        return parse(self.date)

    def __repr__(self):
        attributes = ['date', 'person', 'value']
        values = "\n".join([f'{attribute}: {getattr(self, attribute)}' for attribute in attributes])
        return f'{values}\n\n'


@dataclass
class Chunk:
    id: bytes
    payload: bytes


@dataclass
class SharedFolder:
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
    share_data: str
    sharer: str
    shared_name: str = ''

    @property
    def last_modified_datetime(self):
        return parse(self.last_modified)

    def __repr__(self):
        attributes = ['id', 'name', 'read_only', 'deleted', 'created', 'last_modified', 'sharer']
        values = "\n".join([f'{attribute}: {getattr(self, attribute)}' for attribute in attributes])
        return f'{values}\n\n'
