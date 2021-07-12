import logging
import re
import uuid

from flask import Flask, request, Response
from flask.signals import *

from lowball.authentication import Authentication
from lowball.builtins import DefaultLoggingHandler, DefaultAuthDB, DefaultAuthProvider, default_error_handler, \
    LowballResponse, request_finished_log
from lowball.models.config_models import Config
from lowball.models.provider_models import AuthDatabase, AuthProvider
from lowball.routes.builtins import auth, status


class Lowball(Flask):
    """Core class of a Lowball application.

    This class is an extension of Flask. In addition to the services that Flask provides,
    Lowball controls and configures:
        - Loading YAML configurations and applying them to the application
        - Configuring (if any) authentication providers
        - Sets up logging for the service
        - Sets the default error handler for the application

    :type lowball_config: Config
    :param lowball_config: Config object for the application
    :type logging_handler: type
    :param logging_handler: The handler object for logging in the application -> This will be instantiated on init
    :type auth_database: type
    :param auth_database: The authentication database for the application -> This will be instantiated on init
    :type auth_provider: type
    :param auth_provider: The authentication provider for the application -> This will be instantiated on init
    :type authenticator: Authentication
    :param authenticator: attribute responsible for token operations
    :type error_handler: function
    :param error_handler: The error handler function that will be set as the default
                          error handler for the app
    """
    def __init__(self, config=Config(), logging_handler=DefaultLoggingHandler, auth_database=DefaultAuthDB,
                 auth_provider=DefaultAuthProvider, error_handler=default_error_handler, response_class=LowballResponse,
                 **kwargs):
        if not isinstance(config, Config):
            raise TypeError("config must be a Config object")

        self.lowball_config = config

        super(Lowball, self).__init__(import_name=self.lowball_config.meta.name, **kwargs)

        if logging_handler is None:
            self.logging_handler = None
        elif not issubclass(logging_handler, logging.Handler):
            raise TypeError("logging_handler must subclass logging.Handler")
        else:
            self.logging_handler = logging_handler(**self.lowball_config.logging)
            self.logger.setLevel(self.logging_handler.level)
            self.logger.addHandler(self.logging_handler)

        if auth_provider is None:
            self.auth_provider = None
        elif not issubclass(auth_provider, AuthProvider):
            raise TypeError("auth provide muse be a subclass of AuthProvider")
        else:
            self.auth_provider = auth_provider(**self.lowball_config.auth_provider)

        if auth_database is None:
            self.auth_db = None
        elif not issubclass(auth_database, AuthDatabase):
            raise TypeError("auth_database must be a subclass of AuthDatabase")
        else:
            self.auth_db = auth_database(**self.lowball_config.auth_db)

        if response_class is None:
            self.response_class = LowballResponse
        elif not issubclass(response_class, Response):
            raise TypeError("response_class must be a subclass of flask.Response")
        else:
            self.response_class = response_class

        if error_handler is None:
            self.error_handler = default_error_handler
        else:
            self.error_handler = error_handler

        self.authenticator = Authentication(config=self.lowball_config.authentication)

        self.setup_before_request()
        self.register_blueprint(status)
        self.register_blueprint(auth)

        self.register_request_finished_handler(request_finished_log)

        self.register_error_handler(Exception, self.error_handler)

    def register_template_rendered_handler(self, *subscribers):
        """Connect 1 to n subscribers to the template_rendered signal."""
        for subscriber in subscribers:
            template_rendered.connect(subscriber, self)

    def register_before_render_template_handler(self, *subscribers):
        """Connect 1 to n subscribers to the before_render_template signal."""
        for subscriber in subscribers:
            before_render_template.connect(subscriber, self)

    def register_request_started_handler(self, *subscribers):
        """Connect 1 to n subscribers to the request_started signal."""
        for subscriber in subscribers:
            request_started.connect(subscriber, self)

    def register_request_finished_handler(self, *subscribers):
        """Connect 1 to n subscribers to the request_finished signal."""
        for subscriber in subscribers:
            request_finished.connect(subscriber, self)

    def register_got_request_exception_handler(self, *subscribers):
        """Connect 1 to n subscribers to the got_request_exception signal."""
        for subscriber in subscribers:
            got_request_exception.connect(subscriber, self)

    def register_request_tearing_down_handler(self, *subscribers):
        """Connect 1 to n subscribers to the request_tearing_down signal."""
        for subscriber in subscribers:
            request_tearing_down.connect(subscriber, self)

    def register_appcontext_tearing_down_handler(self, *subscribers):
        """Connect 1 to n subscribers to the appcontext_tearing_down signal."""
        for subscriber in subscribers:
            appcontext_tearing_down.connect(subscriber, self)

    def register_appcontext_pushed_handler(self, *subscribers):
        """Connect 1 to n subscribers to the appcontext_pushed signal."""
        for subscriber in subscribers:
            appcontext_pushed.connect(subscriber, self)

    def register_appcontext_popped_handler(self, *subscribers):
        """Connect 1 to n subscribers to the appcontext_popped signal."""
        for subscriber in subscribers:
            appcontext_popped.connect(subscriber, self)

    def register_message_flashed_handler(self, *subscribers):
        """Connect 1 to n subscribers to the message_flashed signal."""
        for subscriber in subscribers:
            message_flashed.connect(subscriber, self)

    def register_custom_signal_handler(self, signal, *subscribers):
        """Connect 1 to n subscribers to a custom signal signal."""
        for subscriber in subscribers:
            signal.connect(subscriber, self)

    def add_url_rule(self, rule, endpoint=None, view_func=None, provide_automatic_options=None, **options):
        """Ensure that base route is added to all urls.

        This is an override of the flask add_url_rule which allows setting of the "base" route as specified in the
        configuration.
        """
        route = f"/{self.lowball_config.meta.base_route}/{rule}"
        route = re.sub("/{2,}", "/", route)  # squeeze any number of slashes into one slash

        super(Lowball, self).add_url_rule(route, endpoint, view_func, provide_automatic_options, **options)

    def setup_before_request(self):
        @self.before_request
        def add_rid():
            """Add a UUID to each request."""
            request.rid = str(uuid.uuid4())
