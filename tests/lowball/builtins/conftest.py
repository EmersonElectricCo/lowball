import pytest
from flask import Flask

from lowball.builtins.response_class import LowballResponse


@pytest.fixture
def client_with_response_class():
    test_app = Flask("test")
    test_app.config["TESTING"] = True
    test_app.response_class = LowballResponse

    with test_app.test_request_context() as client:
        yield client
