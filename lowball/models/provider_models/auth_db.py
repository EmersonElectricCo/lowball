from abc import ABC, abstractmethod


class AuthDatabase(ABC):
    """Base class for user-defined Auth Database classes.

    The data that is passed into the init is determined by the developer and the config that
    is passed into the init.
    """
    def __init__(self, **kwargs):
        pass

    @abstractmethod
    def add_token(self, token_object):
        """Add a token to the auth database.

        :param token_object: object containing all data to be written by auth db
        :type token_object: Token
        :return: None
        """
        pass

    @abstractmethod
    def lookup_token(self, token_id):
        """Lookup a token in the auth database

        :param token_id: identifier of the token in the auth database
        :type token_id: str
        :return: Token Object
        """
        pass

    @abstractmethod
    def revoke_token(self, token_id):
        """Revoke a token that is stored in the auth database.

        :param token_id: identifier of the token in the auth database
        :type token_id: str
        :return: None
        """
        pass

    @abstractmethod
    def list_tokens(self):
        """List all the tokens that are in the auth database.

        :return: List of Token Objects
        """
        pass

    @abstractmethod
    def list_tokens_by_client_id(self, client_id):
        """List all the tokens for a specific user.

        :param client_id: the username to lookup tokens for
        :type client_id: str
        :return: List of Token Objects
        """
        pass

    @abstractmethod
    def list_tokens_by_role(self, role):
        """List all tokens in the auth database that have a specific role.

        :param role: the role to lookup in the database
        :type role: str
        :return: List of Token Objects
        """
        pass

    @abstractmethod
    def cleanup_tokens(self):
        """Remove all expired tokens from the auth database.

        :return: None
        """
        pass

    @abstractmethod
    def revoke_all(self):
        """Revoke all tokens in the auth database.

        :return: None
        """
        pass
