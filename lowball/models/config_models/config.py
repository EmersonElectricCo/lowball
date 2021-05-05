from pathlib import Path

from ruamel.yaml import YAML

class MetaConfig:
    """Object representation of the Meta config section of a Lowball config.

    Defines metadata about the Lowball application.

    :param name: The name of the Lowball application that is using this config defaults to "lowball"
    :type name: str
    :param base_route: The base route of the Lowball application. This route will
        be at the base of every route in the application. defaults to the root "/"
    :type base_route: str
    :param description: A description of the Lowball application that is using this
        config.
    :type description: str
    :param tags: Tags associated with this Lowball application
    :type tags: list
    """

    # TODO: Implement the ability for someone to add arbitrary metadata

    def __init__(self, name="lowball", base_route="/", description="", tags=None, **kwargs):
        self.name = name
        self.base_route = base_route
        self.description = description
        self.tags = tags

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if not isinstance(value, str):
            raise TypeError("name must be a string")
        self._name = value

    @property
    def base_route(self):
        return self._base_route

    @base_route.setter
    def base_route(self, value):
        if not isinstance(value, str):
            raise TypeError("base_route must be a string")
        if not value.startswith("/"):
            raise ValueError("base_route must start with a forward slash (/)")
        self._base_route = value

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        if not isinstance(value, str):
            raise TypeError("description must be a string")
        self._description = value

    @property
    def tags(self):
        return self._tags

    @tags.setter
    def tags(self, value):
        if value is None:
            value = []
        if not isinstance(value, list):
            raise TypeError("tags must be a list of strings")
        if not all(isinstance(tag, str) for tag in value):
            raise ValueError("all tag values must be strings")
        self._tags = value

    def to_dict(self):
        return {
            "name": self.name,
            "base_route": self.base_route,
            "description": self.description,
            "tags": self.tags
        }


class AuthenticationConfig:
    """Object representation of the Authentication config section of a Lowball config.

    Defines the authentication settings for token generation.

    :param default_token_life: If no token life is requested when generating a token, this value
        is used
    :type default_token_life: int
    :param max_token_life: the maximum number of seconds that a token can be valid for
    :type max_token_life: int
    :param token_secret: The secret that is used to encode JWT tokens for authentication
    :type token_secret: str
    """

    def __init__(self, default_token_life=3600, max_token_life=2592000, token_secret="CHANGE_ME", **kwargs):
        self.default_token_life = default_token_life
        self.max_token_life = max_token_life
        self.token_secret = token_secret

    @property
    def default_token_life(self):
        return self._default_token_life

    @default_token_life.setter
    def default_token_life(self, value):
        if isinstance(value, str):
            try:
                value = int(value)
            except ValueError:
                pass
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("default_token_life must be an integer")
        self._default_token_life = value

    @property
    def max_token_life(self):
        return self._max_token_life

    @max_token_life.setter
    def max_token_life(self, value):
        if isinstance(value, str):
            try:
                value = int(value)
            except ValueError:
                pass
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("max_token_life must be an integer")
        self._max_token_life = value

    @property
    def token_secret(self):
        return self._token_secret

    @token_secret.setter
    def token_secret(self, value):
        if not isinstance(value, str):
            raise TypeError("token secret must be a string")
        self._token_secret = value

    def to_dict(self):
        return {
            "default_token_life": self.default_token_life,
            "max_token_life": self.max_token_life,
            "token_secret": self.token_secret,
        }


def config_from_object(config_object):
    """Generate a Config object from a dictionary object.

    :type config_object: dict
    :param config_object: dictionary representation of a config object
    :rtype: Config
    :return: Object representation of a  Lowball config
    """
    if not isinstance(config_object, dict):
        raise TypeError("config object must be a dictionary")

    meta = MetaConfig(**config_object.get("meta", {}))
    authentication = AuthenticationConfig(**config_object.get("authentication", {}))
    application = config_object.get("application")
    auth_provider = config_object.get("auth_provider")
    auth_db = config_object.get("auth_db")
    logging = config_object.get("logging")

    return Config(meta=meta, authentication=authentication, application=application, auth_provider=auth_provider,
                  auth_db=auth_db, logging=logging)


def config_from_file(filepath):
    """Generate a Config object from the data in a config file.

    Both YAML (.yaml, .yml) and JSON (.json) config files are supported by this
    method. This method will convert the data in either type of file to a dictionary
    and then pass that data to the :func:`config_from_object` method. See documentation
    for that method for information about required data.

    :type filepath: str, :class:`pathlib.Path`
    :param filepath: path to the config file on the system
    :rtype: Config
    :return: Object representation of a  Lowball config
    """
    if not isinstance(filepath, (str, Path)):
        raise TypeError("filepath must be a string or a pathlib.Path object")

    with open(filepath, "r") as config_file:
        config_data = config_file.read()

    try:
        yaml = YAML()
        config_object = dict(yaml.load(config_data))
    except:
        raise ValueError("invalid config format")

    return config_from_object(config_object)


class Config:
    """Object representation of a Lowball config.

    :param meta: Metadata about the Lowball application
    :type meta: MetaConfig
    :param authentication: Data needed for authentication operations
    :type authentication: AuthenticationConfig
    :param application: config data contained in the `application` field of the config
    :type application: dict, optional
    :param auth_provider: config data contained in the `auth_provider` field of the config
    :type auth_provider: dict, optional
    :param auth_db: config data contained in the `auth_db` field of the config
    :type auth_db: dict, optional
    :param logging: config data contained in the `logging` field of the config
    :param kwargs: Used to catch any values that are mapped into the config object that
        are not supported fields. The idea here is to make it very easy to use `Config(**config)`
        without breaking everything. These values are not used or stored.
    :type kwargs: dict
    """

    def __init__(self, meta=MetaConfig(), authentication=AuthenticationConfig(), application=None, auth_provider=None, auth_db=None, logging=None,
                 **kwargs):
        self.meta = meta
        self.authentication = authentication
        self.application = application if application is not None else {}
        self.auth_provider = auth_provider if auth_provider is not None else {}
        self.auth_db = auth_db if auth_db is not None else {}
        self.logging = logging if logging is not None else {}

    @property
    def meta(self):
        return self._meta

    @meta.setter
    def meta(self, value):
        if not isinstance(value, MetaConfig):
            raise TypeError("meta must be a MetaConfig object")
        self._meta = value

    @property
    def authentication(self):
        return self._authentication

    @authentication.setter
    def authentication(self, value):
        if not isinstance(value, AuthenticationConfig):
            raise TypeError("authentication must be a AuthenticationConfig object")
        self._authentication = value

    @property
    def application(self):
        return self._application

    @application.setter
    def application(self, value):
        if not isinstance(value, dict):
            raise TypeError("application must be a dictionary")
        self._application = value

    @property
    def auth_provider(self):
        return self._auth_provider

    @auth_provider.setter
    def auth_provider(self, value):
        if not isinstance(value, dict):
            raise TypeError("auth_provider must be a dictionary")
        self._auth_provider = value

    @property
    def auth_db(self):
        return self._auth_db

    @auth_db.setter
    def auth_db(self, value):
        if not isinstance(value, dict):
            raise TypeError("auth_db must be a dictionary")
        self._auth_db = value

    @property
    def logging(self):
        return self._logging

    @logging.setter
    def logging(self, value):
        if not isinstance(value, dict):
            raise TypeError("logging must be a dictionary")
        self._logging = value

    def to_dict(self):
        """Return a dictionary representation of the Config object."""
        return {
            "meta": self.meta.to_dict(),
            "authentication": self.authentication.to_dict(),
            "application": self.application,
            "auth_provider": self.auth_provider,
            "auth_db": self.auth_db,
            "logging": self.logging
        }


__all__ = [
    "Config",
    "MetaConfig",
    "config_from_object",
    "config_from_file",
    "AuthenticationConfig"
]
