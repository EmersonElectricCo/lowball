from abc import ABC, abstractmethod

from lowball.exceptions import NotImplementedException


class AuthProvider(ABC):
    """Base class for user-defined Auth Provider classes.

    The data that is passed into the init is determined by the developer and the config that
    is passed into the init.
    """

    def __init__(self, **kwargs):
        pass

    @abstractmethod
    def authenticate(self, auth_package):
        """Authenticate using the provided auth package.

        :param auth_package: This should be defined by the developer
        :return: ClientData object
        """
        pass

    @property
    def initialized(self):
        """Property used to determine if the authentication provider is initialized.

        :return: whether this auth provider is initialized.
        :rtype: bool
        """
        return True

    @property
    @abstractmethod
    def auth_package_class(self):
        """Property used to return the AuthPackage class for this AuthProvider.

        :return: AuthPackage class accepted for this auth provider
        """
        pass

    @property
    def create_client_package_class(self):
        """Property used to return the CreateClientPackage class for this AuthProvider.

        :return: CreateClientPackage class accepted for this auth provider
        """
        raise NotImplementedException("create_client_package_class")

    @property
    def client_registration_package_class(self):
        """property used to return the ClientRegistrationPackage class for this auth provider

        :return: ClientRegistrationPackage class accepted for this auth provider

        """

        raise NotImplementedException("client_registration_package_class")

    @property
    def update_client_package_class(self):
        """Property used to return the UpdateClientPackage class for this AuthProvider.

        :return: AuthPackage class accepted for this auth provider
        """
        raise NotImplementedException("update_client_package_class")

    @property
    def self_update_client_package_class(self):
        """Property used to return the SelfUpdateClientPackage class for this AuthProvider.

        :return: AuthPackage class accepted for this auth provider
        """
        raise NotImplementedException("self_update_client_package_class")

    def get_client(self, client_id):
        """Get data for a user.



        :param client_id: user to get data for
        :type client_id: str
        :return: ClientData  or subclass
        """
        raise NotImplementedException("get_client")

    def create_client(self, client_registration_package):
        """Create a client.

        :type client_registration_package: ClientRegistrationPackage
        :param client_registration_package: user to create
        :return: dict or ClientData Object
        """
        raise NotImplementedException("create_client")

    def client_self_register(self, client_registration_package):
        """Allow a user to register themselves.

        This is intended to work the same as :meth:`create_user`, but to
        allow a user to perform the action on themself.

        :type client_registration_package: ClientRegistrationPackage
        :param client_registration_package: user to create
        :return: dict or ClientData Object
        """
        raise NotImplementedException("client_self_register")

    def enable_client(self, client_id):
        """Enable a client.

        :param client_id: client to enable
        :type client_id: str
        :return: dict/ClientData
        """
        raise NotImplementedException("enable_client")

    def disable_client(self, client_id):
        """Disable a user.

        :param client_id: user to disable
        :type client_id: str
        :return: dict
        """
        raise NotImplementedException("disable_client")

    def delete_client(self, client_id):
        """Delete a user.

        :param client_id: user to delete
        :type client_id: str
        :return: dict
        """
        raise NotImplementedException("delete_client")

    def add_roles(self, client_id, roles):
        """Add roles to a client_id

        :param client_id: user to add roles to
        :type client_id: str
        :param roles: list of roles to add to the user
        :type roles: list
        :return: dict/ClientData
        """
        raise NotImplementedException("add_roles")

    def update_client(self, update_client_package, client_id):
        """Update data for a client.

        :param update_client_package: client to update
        :type update_client_package: UpdateClientPackage
        :return: dict/ClientData
        """
        raise NotImplementedException("update_client")

    def client_self_update(self, self_update_client_package, client_id):
        """Allow a client to update data for their user.

        This is intended to work the same as :meth:`update_client`, but
        to allow a client to perform the action on himself.

        :type self_update_client_package: SelfUpdateClientPackage
        :param self_update_client_package: client info to update
        :type client_id: str
        :param client_id: client_id from token of authenticated client
        :return: dict
        """
        raise NotImplementedException("client_self_update")

    def list_clients(self):
        """List clients being tracked.

        :return: list(dict/ClientData)
        """
        raise NotImplementedException("list_clients")

    def delete_roles(self, client_id, roles):
        """Delete roles from a client.

        :param client_id: client to remove roles from
        :type client_id: str
        :param roles: list of roles to remove from the client
        :type roles: list
        :return: dict
        """
        raise NotImplementedException("delete_roles")


class AuthPackage(ABC):
    """Base class for Auth Package definitions.

    The data that is passed into the init is determined by the developer and the config that
    is passed into the init.
    """

    def __init__(self, **kwargs):
        pass


class CreateClientPackage(ABC):
    """Base Class for Client Create Package Definitions

    The data that is passed into init is determined by the developer and should expect a **kwargs style json pass

    """

    def __init__(self, **kwargs):
        pass


class ClientRegistrationPackage(ABC):
    """Base class for Client Registration Package Definitions

    """

    def __init__(self, **kwargs):
        pass


class UpdateClientPackage(ABC):
    """Base Class for Update Client Package Definitions
    """

    def __init__(self, **kwargs):
        pass


class SelfUpdateClientPackage(ABC):
    """Base Class for Self Update Client Package

    This class provides an alternative to the update Client Package to enable developers to differentiate
    what aspects of a client definition the client is able to change about themselves, in case it is different.
    """

    def __init__(self, **kwargs):
        pass
