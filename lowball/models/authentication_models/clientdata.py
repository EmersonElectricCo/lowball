class ClientData:
    """This is a convenience class that is expected to provide basic information about a client id
    This class is meant to be extended to store any other
    client information that is desired by the developers, while still providing a consistent interface which
    lowball can use to determine client_id->roles

    """
    def __init__(self, client_id, roles, **kwargs):
        self.client_id = client_id
        self.roles = roles

    @property
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        if not isinstance(value, str):
            raise TypeError("client_id must be a non-empty string")
        if not value:
            raise ValueError("client_id must be a non-empty string")
        self._client_id = value

    @property
    def roles(self):
        return self._roles

    @roles.setter
    def roles(self, value):
        if not isinstance(value, list):
            raise TypeError("roles must be a list of strings")
        if not all(isinstance(role, str) for role in value):
            raise ValueError("roles must be a list of strings")
        self._roles = value

    def to_dict(self):
        return {
            "client_id": self._client_id,
            "roles": self.roles
        }


__all__ = [
    "ClientData"
]
