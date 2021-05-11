from lowball.models.provider_models.auth_provider import AuthProvider, AuthPackage
from lowball.models.authentication_models import ClientData
from lowball.exceptions import MalformedAuthPackageException, InvalidCredentialsException


class DefaultAuthProvider(AuthProvider):
    """Default Auth Provider for Lowball Applications

    This class was developed to allow for a user to make full use of a Lowball
    application without having to create their own authentication provider.

    :param username: the username that is required for authentication
    :type username: str
    :param password: the password that is required for authentication
    :type password: str
    """
    def __init__(self, username="admin", password="nimda"):
        super(DefaultAuthProvider, self).__init__()

        if not isinstance(username, str):
            raise TypeError("username must be a string")
        self._username = username

        if not isinstance(password, str):
            raise TypeError("password must be a string")
        self._password = password

    @property
    def username(self):
        """Get the username needed for authentication"""
        return self._username

    @username.setter
    def username(self, value):
        """Can't set username after init"""
        raise PermissionError("cannot set username after init")

    @property
    def password(self):
        """Get the password needed for authentication"""
        return self._password

    @password.setter
    def password(self, value):
        """Can't set password after init"""
        raise PermissionError("cannot set password after init")

    def authenticate(self, auth_package):
        """Authenticate a user.

        Using this authentication provider, a user can authenticate if the auth package
        that he passes in contains the same username and password as those configured in
        the init of this class. If they do match, then the user will be considered
        authenticated and given the admin role.

        :param auth_package: data needed to authenticate with this provider
        :type auth_package: DefaultAuthPackage
        :return: auth data
        :rtype: AuthData
        """
        if isinstance(auth_package, self.auth_package_class):
            username = auth_package.username
            password = auth_package.password
        else:
            raise MalformedAuthPackageException

        if self.username == username and self.password == password:
            return ClientData(client_id=username, roles=["admin"])
        else:
            raise InvalidCredentialsException

    def get_client(self, client_id):
        if client_id == self.username:
            return ClientData(client_id=self.username, roles=["admin"])
        return None

    @property
    def auth_package_class(self):
        """The auth package class that this class' `authenticate` method accepts."""
        return DefaultAuthPackage


class DefaultAuthPackage(AuthPackage):
    """
    Simple auth package class for use in the default auth provider.
    """
    def __init__(self, username, password, **kwargs):
        super(DefaultAuthPackage, self).__init__(**kwargs)
        self.username = username
        self.password = password

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        if not isinstance(value, str):
            raise TypeError("username must be a string")
        self._username = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        if not isinstance(value, str):
            raise TypeError("password must be a string")
        self._password = value


__all__ = [
    "DefaultAuthProvider",
    "DefaultAuthPackage"
]
