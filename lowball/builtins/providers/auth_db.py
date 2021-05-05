import datetime
from pathlib import Path

from ruamel.yaml import YAML

from lowball.models.authentication_models import Token, valid_token_id
from lowball.models.provider_models.auth_db import AuthDatabase
import re

class DefaultAuthDB(AuthDatabase):
    """Default Auth Database for Lowball Applications

    This class was developed to allow for a user to make full use of a Lowball
    application without having to create their own auth database provider. It makes
    use of the file system to store tokens.

    :param token_path: the base file system path at which tokens will be stored.
    :type token_path: str, Path
    """
    _YAML = YAML()

    def __init__(self, token_path=Path("/var/lib/lowball/authentication/tokens")):
        super(DefaultAuthDB, self).__init__()
        self.token_path = token_path

        try:
            self.token_path.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            raise PermissionError("Lacking permissions to store tokens at configured route")

    @property
    def token_path(self):
        return self._token_path

    @token_path.setter
    def token_path(self, value):
        if not isinstance(value, (str, Path)):
            raise TypeError("token_path must be a string or a Path object")

        self._token_path = Path(value)

    def _dump_token(self, token_data):
        """Write a token to the file system.

        This will "store" a token on the system, i.e. writing token data to a
        flat file at the `token_path` location in YAML format.

        :param token_data: token metadata
        :type token_data: Token
        :return: None
        """
        token_id = token_data.token_id

        if not valid_token_id(token_id):
            raise ValueError(f"invalid token_id: {token_id}")

        token_file = open(self.token_path.joinpath(token_id), "w")

        self._YAML.dump(token_data.to_dict(), token_file)

    def _load_token(self, token_id):
        """Load token data from the file system into a token object.

        If there is a token file for the given token ID, but the data cannot be loaded
        into a Token object, then the file will automatically be deleted by this
        method, as this could cause issues with other operations.

        :param token_id: the identifier of the token to be loaded
        :return: token object
        :rtype: Token
        """
        if not valid_token_id(token_id):
            raise ValueError(f"invalid token_id: {token_id}")

        token_file = self.token_path.joinpath(token_id)

        if not token_file.exists():
            return None

        with open(token_file, "r") as f:
            data = self._YAML.load(f)

        try:
            return Token(**data)
        except (TypeError, ValueError):
            self._delete_token(token_id)

    def _delete_token(self, token_id):
        """Delete a token file from the file system.

        :param token_id: identifier of the token to delete
        :type token_id: str, Token
        :return: None
        """
        if not valid_token_id(token_id):
            raise ValueError(f"invalid token_id: {token_id}")

        token_file = self.token_path.joinpath(token_id)

        try:
            token_file.unlink()
        except FileNotFoundError:
            pass

    def add_token(self, token_object):
        """Add a token to the database."""
        self._dump_token(token_object)

    def lookup_token(self, token_id):
        """Lookup a token in the database."""
        return self._load_token(token_id)

    def revoke_token(self, token_id):
        """Remove a token from the database."""
        if isinstance(token_id, Token):
            token_id = token_id.token_id

        self._delete_token(token_id)

    def list_tokens(self):
        """List all the tokens in the database."""
        if not self.token_path.exists():
            return []

        tokens = []

        for token in self.token_path.iterdir():
            token = self._load_token(token)

            if token:
                tokens.append(token)

        return tokens

    def list_tokens_by_client_id(self, client_id):
        """List all the tokens in the database associated with a specific user."""
        tokens = self.list_tokens()

        return [token for token in tokens if token.client_id == client_id]

    def list_tokens_by_role(self, role):
        """List all the tokens in the database that have the specified role."""
        tokens = self.list_tokens()

        return [token for token in tokens if role in token.roles]

    def cleanup_tokens(self):
        """Remove all expired tokens from the database."""
        now = datetime.datetime.utcnow()
        tokens = self.list_tokens()

        expired = [token for token in tokens if now > token.expiration]

        for token in expired:
            self._delete_token(token.token_id)

    def revoke_all(self):
        """Remove all tokens from the database."""
        tokens = self.list_tokens()

        for token in tokens:
            self._delete_token(token.token_id)


__all__ = [
    "DefaultAuthDB"
]
