from logging import INFO
from unittest.mock import Mock

import flask
import pytest


########################
# App Context Fixtures #
########################
@pytest.fixture
def test_client():
    test_app = flask.Flask("test_app")
    test_app.config["TESTING"] = True
    test_app.logger._log = Mock()
    test_app.logger.setLevel(INFO)
    return test_app


@pytest.fixture(params=[1, 2])
def context_no_request_env(test_client, request):
    with test_client.test_request_context() as app_context:
        old_environ = flask.request.environ

        if request.param == 1:
            del flask.request.environ
        else:
            flask.request.environ = None

        yield app_context

        # Reset the environment to the old value, other wise
        # there is an error in tearing down the application.
        flask.request.environ = old_environ


@pytest.fixture(params=["USERAGENTSTRING", None])
def http_user_agent(request):
    if request.param is not None:
        return request.param


@pytest.fixture(params=["2.2.2.2", None])
def http_x_forwarded_for(request):
    if request.param is not None:
        return request.param


@pytest.fixture
def context_normal_env(test_client, http_user_agent, http_x_forwarded_for, token):
    with test_client.test_request_context() as app_context:
        if http_x_forwarded_for:
            flask.request.environ["HTTP_X_FORWARDED_FOR"] = http_x_forwarded_for

        if http_user_agent:
            flask.request.environ["HTTP_USER_AGENT"] = http_user_agent

        flask.request.environ["REMOTE_ADDR"] = "1.1.1.1"
        flask.g.client_data = token
        # flask.request.method = "GET"

        yield app_context


@pytest.fixture
def context_exception_env(context_normal_env):
    flask.g.response_is_exception = True
    flask.g.response_exception_log_data = "TESTDATANOTREALEXCEPTION"


#####################
# Response Fixtures #
#####################
@pytest.fixture
def base_response():
    return flask.Response()


@pytest.fixture
def exception_response(base_response):
    base_response.status_code = 500
    base_response.status = "500 Internal Server Error"
    return base_response
