import json

from datetime import datetime

import re
from random import choice


TOKEN_ID_PATTERN = r"[a-zA-Z0-9]{16}"
TOKEN_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def generate_token_id():
    # generates a 16 byte token consisting of a-zA-Z0-9
    return "".join(choice(TOKEN_ID_ALPHABET) for i in range(0, 16))


def valid_token_id(token_id):
    try:
        return re.fullmatch(TOKEN_ID_PATTERN, token_id) is not None
    except:
        return False


class Token:
    """Token object

    This object stores data that is needed to create the JWT tokens that are
    the primary means of authentication in Lowball microservices.

    :param cid: the client id that will be issued a token
    :type cid: str
    :param r: list of roles that the client has
    :type r: list
    :param cts: the time that the token was created
    :type cts: datetime, str
    :param ets: the time that the token expires
    :type ets: datetime, str
    :param rcid: the client id of the entity issuing the token
    :type rcid: str
    :param tid: identifier of the token that is generated
    :type tid: str
    """
    _DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

    def __init__(self, cid, r, cts, ets, rcid, tid, **kwargs):
        self.client_id = cid
        self.roles = r
        self.created = cts
        self.expiration = ets
        self.issued_by = rcid
        self.token_id = tid

    def __eq__(self, other):
        return other.__class__ == self.__class__ and hash(self) == hash(other)

    def __hash__(self):
        return hash(json.dumps(self.to_dict()))

    @property
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        if not isinstance(value, str):
            raise TypeError("client_id must be a string")
        self._client_id = value

    @property
    def roles(self):
        return self._roles

    @roles.setter
    def roles(self, value):
        if not isinstance(value, list):
            raise TypeError("roles must be a list of strings")
        if not all(isinstance(role, str) for role in value):
            raise ValueError("all roles must be strings")
        self._roles = value

    @property
    def created(self):
        return self._created

    @created.setter
    def created(self, value):
        if isinstance(value, str):
            value = datetime.strptime(value, self._DATE_FORMAT)
        if not isinstance(value, datetime):
            raise TypeError("created must be a datetime object")
        self._created = value

    @property
    def expiration(self):
        return self._expiration

    @expiration.setter
    def expiration(self, value):
        if isinstance(value, str):
            value = datetime.strptime(value, self._DATE_FORMAT)
        if not isinstance(value, datetime):
            raise TypeError("expiration must be a datetime object")
        self._expiration = value

    @property
    def issued_by(self):
        return self._issued_by

    @issued_by.setter
    def issued_by(self, value):
        if not isinstance(value, str):
            raise TypeError("issued_by must be a string")
        self._issued_by = value

    @property
    def token_id(self):
        return self._token_id

    @token_id.setter
    def token_id(self, value):
        if not isinstance(value, str):
            raise TypeError("token_id must be a string")
        if not valid_token_id(value):
            raise ValueError("token_id must match the pattern [a-zA-Z0-9]{16}")
        self._token_id = value

    def to_dict(self):
        """Return a dictionary representation of a Token object."""
        return {
            "cid": self.client_id,
            "r": self.roles,
            "cts": datetime.strftime(self.created, self._DATE_FORMAT),
            "ets": datetime.strftime(self.expiration, self._DATE_FORMAT),
            "rcid": self.issued_by,
            "tid": self.token_id
        }


__all__ = [
    "Token",
    "generate_token_id",
    "valid_token_id",
    "TOKEN_ID_PATTERN"
]
