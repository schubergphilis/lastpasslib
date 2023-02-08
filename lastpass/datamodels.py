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

    def __str__(self):
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

    def __str__(self):
        attributes = ['date', 'person', 'value']
        values = "\n".join([f'{attribute}: {getattr(self, attribute)}' for attribute in attributes])
        return f'{values}\n\n'


@dataclass
class Chunk:
    id: bytes
    payload_size: bytes
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

    def __str__(self):
        attributes = ['id', 'name', 'read_only', 'deleted', 'created', 'last_modified', 'sharer']
        values = "\n".join([f'{attribute}: {getattr(self, attribute)}' for attribute in attributes])
        return f'{values}\n\n'


@dataclass
class NeverUrl:
    id: int
    url: str


@dataclass
class EquivalentDomain:
    id: int
    url: str


@dataclass
class UrlRule:
    url: str
    exact_host: bool
    exact_port: bool
    case_insensitive: bool


@dataclass
class CompanyUser:
    email: str
    img: str
    name: str
    type: str
    uid: str


@dataclass
class ShareAction:
    company_username: str
    date: str
    email: str
    give: str
    share_date: str
    state: str
    _uid: str

    @property
    def id(self):
        return self._uid

    @property
    def share_datetime(self):
        return parse(self.share_date)

    @property
    def datetime(self):
        return parse(self.date)

    @property
    def accepted(self):
        return bool(int(self.state))

    @property
    def given(self):
        return bool(int(self.give))
