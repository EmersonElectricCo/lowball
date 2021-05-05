import datetime
import uuid

import jwt

from lowball.exceptions import InvalidAuthDataException, InvalidRequestingUserException, InvalidTokenLifeException, \
    InvalidTokenException, BadRequestException
from lowball.models.authentication_models import Token, valid_token_id, generate_token_id
from lowball.models.config_models import AuthenticationConfig


class Authentication:
    """Object used to generate and decode tokens used in Lowball applications.

    This object is to be used in all Lowball applications, and is in charge
    of all operations surrounding tokens. Currently, this means creation, decoding,
    and validation of tokens.

    :param config: config data needed for token operations
    :type config: AuthenticationConfig
    """

    def __init__(self, config):
        self.config = config

    @property
    def config(self):
        return self._config

    @config.setter
    def config(self, value):
        if not isinstance(value, AuthenticationConfig):
            raise TypeError("config must be a AuthenticationConfig object")
        self._config = value

    def create_token(self, client_id, roles=[], requesting_client=None, expiration=None):
        """Create a JWT token for use in Lowball applications.

        :param client_id: client id for the token
        :type client_id: str
        :param roles: list of roles to give the client
        :type roles: list(str)
        :param requesting_client: The user requesting the token
        :type requesting_client: str
        :param expiration: time of expiration for this token
        :type expiration: datetime
        :return: Token and token data
        :rtype: str, Token
        """

        if not client_id or not isinstance(client_id, str):
            raise BadRequestException("Invalid client id")

        if not roles:
            roles = []
        if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
            raise BadRequestException("Roles must be a list of strings")

        if requesting_client is not None and not isinstance(requesting_client, str):
            raise BadRequestException("Invalid requesting client id")

        now = datetime.datetime.utcnow()

        if not requesting_client:
            requesting_client = client_id

        if expiration is None:
            expiration = now + datetime.timedelta(seconds=self.config.default_token_life)

        token_id = generate_token_id()
        token_data = Token(cid=client_id, r=roles, cts=now, ets=expiration,
                           rcid=requesting_client, tid=token_id)

        if token_data.expiration - now > datetime.timedelta(seconds=self.config.max_token_life):
            raise InvalidTokenLifeException

        token = jwt.encode(token_data.to_dict(), self.config.token_secret, algorithm="HS256")

        return token, token_data

    def decode_token(self, token):
        """Decode a Lowball token.

        :param token: JWT Lowball token string
        :type token: str
        :return: token data object
        :rtype: Token
        """
        try:
            payload = jwt.decode(token, self.config.token_secret, algorithms=["HS256"])
        except Exception as err:
            raise InvalidTokenException(str(err))
        return Token(**payload)

    def validate_token(self, token):
        """Validate a Lowball token.

        The conditions that need to be met for a Lowball token to be valid is that:
        1. The token is able to be decoded using the `decode_token` method
        2. The token is not expired

        :param token: JWT Lowball token string
        :type token: str
        :return: Whether the token is valid
        :rtype: bool
        """
        try:
            token_data = self.decode_token(token)
            now = datetime.datetime.utcnow()
            return token_data.expiration > now
        except:
            return False


__all__ = [
    "Authentication"
]
