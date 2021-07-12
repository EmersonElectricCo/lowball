import logging
from unittest.mock import call

import flask
import pytest

from lowball import Lowball
from lowball.authentication import Authentication
from lowball.builtins import DefaultAuthProvider, DefaultAuthDB, DefaultLoggingHandler, default_error_handler, \
    LowballResponse, request_finished_log
from lowball.models.provider_models.auth_db import AuthDatabase
from lowball.models.provider_models.auth_provider import AuthProvider
from lowball.routes.builtins import status, auth


class TestLowballCoreInit:
    def test_init_raises_exception_when_incorrect_type_passed_in_for_config(self):
        with pytest.raises(TypeError):
            Lowball(config=1, logging_handler=DefaultLoggingHandler, auth_database=DefaultAuthDB,
                    auth_provider=DefaultAuthProvider, default_error_handler=default_error_handler)

    def test_passing_none_to_provider_configs_does_not_produce_errors(self, lowball_config, mocked_lowball_init,
                                                                      mocked_mkdir):
        app = Lowball(config=lowball_config, logging_handler=None, auth_provider=None, auth_database=None,
                      error_handler=None, response_class=None)

        assert app.logging_handler is None
        assert app.auth_provider is None
        assert app.auth_db is None
        assert app.error_handler == default_error_handler
        assert app.response_class == LowballResponse
        assert isinstance(app.authenticator, Authentication)

        assert len(app.logger.handlers) == 0  # This means that no handler was added during init
        flask.Flask.register_blueprint.assert_called()

        assert app.before_request_funcs[None][0].__name__ == "add_rid"

    def test_init_performs_all_necessary_actions(self, lowball_config, mocked_lowball_init, mocked_mkdir):
        app = Lowball(config=lowball_config, logging_handler=DefaultLoggingHandler, auth_database=DefaultAuthDB,
                      auth_provider=DefaultAuthProvider, error_handler=default_error_handler,
                      response_class=LowballResponse)

        assert isinstance(app.logging_handler, logging.Handler)
        assert isinstance(app.auth_provider, AuthProvider)
        assert isinstance(app.auth_db, AuthDatabase)
        assert isinstance(app.authenticator, Authentication)
        assert app.error_handler == default_error_handler
        assert app.response_class == LowballResponse

        assert app.logging_handler in app.logger.handlers
        assert app.logger.level == app.logging_handler.level
        flask.Flask.register_blueprint.assert_has_calls([call(status), call(auth)], any_order=True)

        # Assert that the `add_rid` function was added to before_request_funcs
        assert app.before_request_funcs[None][0].__name__ == "add_rid"

        flask.Flask.register_error_handler.assert_called_with(Exception, default_error_handler)
        app.register_request_finished_handler.assert_called_once_with(request_finished_log)

    @pytest.mark.parametrize("logging_handler, authentication_database, authentication_provider, response_class", [
        (1, DefaultAuthDB, DefaultAuthProvider, LowballResponse),
        (DefaultLoggingHandler, 1, DefaultAuthProvider, LowballResponse),
        (DefaultLoggingHandler, DefaultAuthDB, 1, LowballResponse),
        (DefaultLoggingHandler, DefaultAuthDB, DefaultAuthProvider, 1)
    ])
    def test_passing_incorrect_types_to_init_raises_exception(self, lowball_config, logging_handler,
                                                              authentication_database, authentication_provider,
                                                              response_class, mocked_mkdir):
        with pytest.raises(TypeError):
            Lowball(config=lowball_config, logging_handler=logging_handler, auth_provider=authentication_provider,
                    auth_database=authentication_database, response_class=response_class)


class TestLowballCoreSignalHandlers:
    # Template Rendered
    def test_template_rendered_handler_connects_single_function(self, lowball_app, signal_subscriber,
                                                                mocked_signals):
        lowball_app.register_template_rendered_handler(signal_subscriber)
        flask.template_rendered.connect.assert_called_once_with(signal_subscriber, lowball_app)

    def test_template_rendered_handler_connects_multiple_functions(self, lowball_app, signal_subscriber,
                                                                   other_signal_subscriber, mocked_signals):
        lowball_app.register_template_rendered_handler(signal_subscriber, other_signal_subscriber)
        flask.template_rendered.connect.assert_has_calls([
            call(signal_subscriber, lowball_app),
            call(other_signal_subscriber, lowball_app)
        ])

    # Before Render Template
    def test_before_render_template_handler_connects_single_function(self, lowball_app, signal_subscriber,
                                                                     mocked_signals):
        lowball_app.register_before_render_template_handler(signal_subscriber)
        flask.before_render_template.connect.assert_called_once_with(signal_subscriber, lowball_app)

    def test_before_render_template_handler_connects_multiple_functions(self, lowball_app, signal_subscriber,
                                                                        other_signal_subscriber, mocked_signals):
        lowball_app.register_before_render_template_handler(signal_subscriber, other_signal_subscriber)
        flask.before_render_template.connect.assert_has_calls([
            call(signal_subscriber, lowball_app),
            call(other_signal_subscriber, lowball_app)
        ])

    # Request Started
    def test_request_started_handler_connects_single_function(self, lowball_app, signal_subscriber,
                                                              mocked_signals):
        lowball_app.register_request_started_handler(signal_subscriber)
        flask.request_started.connect.assert_called_once_with(signal_subscriber, lowball_app)

    def test_request_started_handler_connects_multiple_functions(self, lowball_app, signal_subscriber,
                                                                 other_signal_subscriber, mocked_signals):
        lowball_app.register_request_started_handler(signal_subscriber, other_signal_subscriber)
        flask.request_started.connect.assert_has_calls([
            call(signal_subscriber, lowball_app),
            call(other_signal_subscriber, lowball_app)
        ])

    # Request Finished
    def test_request_finished_handler_connects_single_function(self, lowball_app, signal_subscriber,
                                                               mocked_signals):
        lowball_app.register_request_finished_handler(signal_subscriber)
        flask.request_finished.connect.assert_called_once_with(signal_subscriber, lowball_app)

    def test_request_finished_handler_connects_multiple_functions(self, lowball_app, signal_subscriber,
                                                                  other_signal_subscriber, mocked_signals):
        lowball_app.register_request_finished_handler(signal_subscriber, other_signal_subscriber)
        flask.request_finished.connect.assert_has_calls([
            call(signal_subscriber, lowball_app),
            call(other_signal_subscriber, lowball_app)
        ])

    # Got Request Exception
    def test_got_request_exception_handler_connects_single_function(self, lowball_app, signal_subscriber,
                                                                    mocked_signals):
        lowball_app.register_got_request_exception_handler(signal_subscriber)
        flask.got_request_exception.connect.assert_called_once_with(signal_subscriber, lowball_app)

    def test_got_request_exception_handler_connects_multiple_functions(self, lowball_app, signal_subscriber,
                                                                       other_signal_subscriber, mocked_signals):
        lowball_app.register_got_request_exception_handler(signal_subscriber, other_signal_subscriber)
        flask.got_request_exception.connect.assert_has_calls([
            call(signal_subscriber, lowball_app),
            call(other_signal_subscriber, lowball_app)
        ])

    # Request Tearing Down
    def test_request_tearing_down_handler_connects_single_function(self, lowball_app, signal_subscriber,
                                                                   mocked_signals):
        lowball_app.register_request_tearing_down_handler(signal_subscriber)
        flask.request_tearing_down.connect.assert_called_once_with(signal_subscriber, lowball_app)

    def test_request_tearing_down_handler_connects_multiple_functions(self, lowball_app, signal_subscriber,
                                                                      other_signal_subscriber, mocked_signals):
        lowball_app.register_request_tearing_down_handler(signal_subscriber, other_signal_subscriber)
        flask.request_tearing_down.connect.assert_has_calls([
            call(signal_subscriber, lowball_app),
            call(other_signal_subscriber, lowball_app)
        ])

    # Appcontext Tearing Down
    def test_appcontext_tearing_down_handler_connects_single_function(self, lowball_app, signal_subscriber,
                                                                      mocked_signals):
        lowball_app.register_appcontext_tearing_down_handler(signal_subscriber)
        flask.appcontext_tearing_down.connect.assert_called_once_with(signal_subscriber, lowball_app)

    def test_appcontext_tearing_down_handler_connects_multiple_functions(self, lowball_app, signal_subscriber,
                                                                         other_signal_subscriber, mocked_signals):
        lowball_app.register_appcontext_tearing_down_handler(signal_subscriber, other_signal_subscriber)
        flask.appcontext_tearing_down.connect.assert_has_calls([
            call(signal_subscriber, lowball_app),
            call(other_signal_subscriber, lowball_app)
        ])

    # Appcontext Pushed
    def test_appcontext_pushed_handler_connects_single_function(self, lowball_app, signal_subscriber,
                                                                mocked_signals):
        lowball_app.register_appcontext_pushed_handler(signal_subscriber)
        flask.appcontext_pushed.connect.assert_called_once_with(signal_subscriber, lowball_app)

    def test_appcontext_pushed_handler_connects_multiple_functions(self, lowball_app, signal_subscriber,
                                                                   other_signal_subscriber, mocked_signals):
        lowball_app.register_appcontext_pushed_handler(signal_subscriber, other_signal_subscriber)
        flask.appcontext_pushed.connect.assert_has_calls([
            call(signal_subscriber, lowball_app),
            call(other_signal_subscriber, lowball_app)
        ])

    # Appcontext Popped
    def test_appcontext_popped_handler_connects_single_function(self, lowball_app, signal_subscriber,
                                                                mocked_signals):
        lowball_app.register_appcontext_popped_handler(signal_subscriber)
        flask.appcontext_popped.connect.assert_called_once_with(signal_subscriber, lowball_app)

    def test_appcontext_popped_handler_connects_multiple_functions(self, lowball_app, signal_subscriber,
                                                                   other_signal_subscriber, mocked_signals):
        lowball_app.register_appcontext_popped_handler(signal_subscriber, other_signal_subscriber)
        flask.appcontext_popped.connect.assert_has_calls([
            call(signal_subscriber, lowball_app),
            call(other_signal_subscriber, lowball_app)
        ])

    # Message Flashed
    def test_message_flashed_handler_connects_single_function(self, lowball_app, signal_subscriber,
                                                              mocked_signals):
        lowball_app.register_message_flashed_handler(signal_subscriber)
        flask.message_flashed.connect.assert_called_once_with(signal_subscriber, lowball_app)

    def test_message_flashed_handler_connects_multiple_functions(self, lowball_app, signal_subscriber,
                                                                 other_signal_subscriber, mocked_signals):
        lowball_app.register_message_flashed_handler(signal_subscriber, other_signal_subscriber)
        flask.message_flashed.connect.assert_has_calls([
            call(signal_subscriber, lowball_app),
            call(other_signal_subscriber, lowball_app)
        ])

    def test_custom_signal_handler_connects_single_function(self, lowball_app, signal_subscriber, mocked_signals,
                                                            custom_signal):
        lowball_app.register_custom_signal_handler(custom_signal, signal_subscriber)
        custom_signal.connect.assert_called_once_with(signal_subscriber, lowball_app)

    def test_custom_signal_handler_connects_multiple_functions(self, lowball_app, signal_subscriber, mocked_signals,
                                                               other_signal_subscriber, custom_signal):
        lowball_app.register_custom_signal_handler(custom_signal, signal_subscriber, other_signal_subscriber)
        custom_signal.connect.assert_has_calls([
            call(signal_subscriber, lowball_app),
            call(other_signal_subscriber, lowball_app)
        ])


class TestLowballCoreAddURLRule:
    @pytest.mark.parametrize("rule, expected_result", [
        ("/", "/base/route/"),
        ("/test", "/base/route/test")
    ])
    def test_add_url_rule_properly_adds_base_route(self, lowball_app, rule, expected_result):
        def test_view_func():
            pass

        lowball_app.add_url_rule(rule, endpoint="test_view_func", view_func=test_view_func, strict_slashes=False)

        url_map = lowball_app.url_map
        rules = {route.endpoint: route.rule for route in url_map.iter_rules()}
        assert rules["test_view_func"] == expected_result
