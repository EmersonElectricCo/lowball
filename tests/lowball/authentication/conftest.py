import pytest
import datetime
import uuid

from flask import Flask
from werkzeug.datastructures import Headers
import jwt

import lowball.models.config_models
from lowball.authentication.authentication import Authentication
from lowball.models.authentication_models import Token, ClientData, generate_token_id
from lowball.exceptions import InvalidTokenException
from unittest.mock import Mock
import lowball


@pytest.fixture
def bad_expiration():
    return datetime.datetime(2030, 1, 1)


@pytest.fixture(params=[1, "string", True, object(), {}, [], None])
def not_auth_config(request):
    return request.param


@pytest.fixture(params=[1, "string", True, object(), {}, []])
def not_logger(request):
    return request.param


@pytest.fixture(autouse=True)
def patched_uuid4(monkeypatch, token_id):
    monkeypatch.setattr(uuid, "uuid4", lambda: token_id)

@pytest.fixture(autouse=True)
def patched_generate_token(token_id, monkeypatch):
    monkeypatch.setattr(lowball.authentication.authentication, "generate_token_id", Mock(return_value=token_id))



@pytest.fixture
def create_token1(token_id, fake_now, all_roles):
    return Token(
        cid="username1",
        r=all_roles,
        cts=fake_now,
        ets=datetime.datetime(2020, 2, 1),
        rcid="username2",
        tid=token_id
    )

@pytest.fixture
def create_token2(token_id, fake_now, all_roles):
    return Token(
        cid="username1",
        r=all_roles,
        cts=fake_now,
        ets=datetime.datetime(2020, 2, 1),
        rcid="username1",
        tid=token_id
    )

@pytest.fixture
def create_token3(token_id, fake_now, all_roles):
    return Token(
        cid="username1",
        r=all_roles,
        cts=fake_now,
        ets=datetime.datetime(2020, 1, 1, 0, 30),
        rcid="username2",
        tid=token_id
    )

@pytest.fixture(params=["requesting_user", "no_requesting_user", "no_expiration"])
def token_create_rounds(request, client_data, create_token1, create_token2, create_token3, token_secret):
    # return
    if request.param == "requesting_user":

        return client_data, "username2", datetime.datetime(2020, 2, 1), datetime.datetime(2020, 2, 1), jwt.encode(create_token1.to_dict(), token_secret)

    if request.param == "no_requesting_user":

        return client_data, None, datetime.datetime(2020, 2, 1), datetime.datetime(2020, 2, 1), jwt.encode(create_token2.to_dict(), token_secret)

    if request.param == "no_expiration":

        return client_data, "username2", None, datetime.datetime(2020, 1, 1, 0, 30), jwt.encode(create_token3.to_dict(), token_secret)

@pytest.fixture(params=[0,1,2])
def bad_token_rounds(request, invalid_expected_token_string):
    if request.param == 0:
        return "notevenkindofatoken"
    elif request.param == 1:
        return invalid_expected_token_string
    elif request.param == 2:
        return ["not", "even", "a", "string"]

@pytest.fixture
def decoded_data(token_id):
    return Token(
        cid="username1",
        r=['admin', 'lead', 'analyst'],
        cts='2020-01-01 00:00:00',
        ets='2020-01-01 00:30:00',
        rcid="username1",
        tid=token_id
    )


@pytest.fixture(params=[None, "username1"])
def requesting_user(request):
    return request.param


@pytest.fixture(params=[datetime.datetime(2020, 1, 2), "2020-01-02 00:00:00"])
def expiration(request):
    return request.param


@pytest.fixture(params=[None, 1, True, "string", {}, [], object()])
def not_auth_data(request):
    return request.param


@pytest.fixture(params=[1, True, {}, [], object()])
def not_user(request):
    return request.param


@pytest.fixture
def request_no_headers(client, headers):
    with client.test_client():
        with client.test_request_context(headers=headers) as client:
            yield client


@pytest.fixture
def request_invalid_headers(client, headers_invalid_auth):
    with client.test_client():
        with client.test_request_context(headers=headers_invalid_auth) as client:
            yield client


@pytest.fixture
def request_token_not_in_db(client, headers_with_token, token_id, monkeypatch):
    def mocked_decode_token(self, token):
        return Token(
            cid="username",
            r=[],
            cts=datetime.datetime(2019, 11, 1),
            ets=datetime.datetime(2020, 12, 1),
            rcid="another_user",
            tid=token_id
        )

    def mocked_lookup_token(token):
        raise InvalidTokenException

    client.auth_db.lookup_token = mocked_lookup_token

    with client.test_client():
        with client.test_request_context(headers=headers_with_token) as client:
            monkeypatch.setattr(Authentication, "decode_token", mocked_decode_token)
            yield client


@pytest.fixture
def request_unmatched_token(client, headers_with_token, token_id, monkeypatch):
    def mocked_decode_token(self, token):
        return Token(
            cid="username",
            r=[],
            cts=datetime.datetime(2019, 11, 1),
            ets=datetime.datetime(2020, 12, 1),
            rcid="another_user",
            tid=token_id
        )

    def mocked_lookup_token(token):
        return Token(
            cid="different_user",
            r=[],
            cts=datetime.datetime(2019, 11, 1),
            ets=datetime.datetime(2020, 12, 1),
            rcid="another_user",
            tid=token_id
        )

    client.auth_db.lookup_token = mocked_lookup_token

    with client.test_client():
        with client.test_request_context(headers=headers_with_token) as client:
            monkeypatch.setattr(Authentication, "decode_token", mocked_decode_token)
            yield client


@pytest.fixture
def request_valid_token(client, headers_with_token, token_id, monkeypatch, expected_token):
    def mocked_decode_token(self, token):
        return expected_token

    def mocked_lookup_token(token):
        return expected_token

    client.auth_db.lookup_token = mocked_lookup_token

    with client.test_client():
        with client.test_request_context(headers=headers_with_token) as client:
            monkeypatch.setattr(Authentication, "decode_token", mocked_decode_token)
            yield client


@pytest.fixture
def request_token_expired(client, headers_with_token, token_id, monkeypatch):
    def mocked_decode_token(self, token):
        return Token(
            cid="username",
            r=[],
            cts=datetime.datetime(2019, 11, 1),
            ets=datetime.datetime(2019, 12, 1),
            rcid="another_user",
            tid=token_id
        )

    with client.test_client():
        with client.test_request_context(headers=headers_with_token) as client:
            monkeypatch.setattr(Authentication, "decode_token", mocked_decode_token)
            yield client


@pytest.fixture
def request_token_no_roles(client, headers_with_token, token_id, monkeypatch, expected_token):
    def mocked_decode_token(self, token):
        return expected_token

    def mocked_lookup_token(token):
        return expected_token

    client.auth_db.lookup_token = mocked_lookup_token

    with client.test_client():
        with client.test_request_context(headers=headers_with_token) as client:
            monkeypatch.setattr(Authentication, "decode_token", mocked_decode_token)
            yield client


@pytest.fixture(params=[
    ["admin"],
    ["admin", "lead"],
    ["admin", "lead", "analyst"],
    ["admin", "analyst"],
    ["lead"],
    ["lead", "analyst"],
    ["analyst"]
])
def request_admin_or_lead_or_analyst_token(request, client, headers_with_token, expected_token, monkeypatch):
    expected_token.roles = request.param

    def mocked_decode_token(self, token):
        return expected_token

    def mocked_lookup_token(token):
        return expected_token

    client.auth_db.lookup_token = mocked_lookup_token

    with client.test_client():
        with client.test_request_context(headers=headers_with_token) as client:
            monkeypatch.setattr(Authentication, "decode_token", mocked_decode_token)
            yield client


@pytest.fixture(params=[
    ["admin"],
    ["admin", "lead"],
    ["admin", "lead", "analyst"],
    ["admin", "analyst"]
])
def request_admin_token(request, client, headers_with_token, expected_token, monkeypatch):
    expected_token.roles = request.param
    
    def mocked_decode_token(self, token):
        return expected_token

    def mocked_lookup_token(token):
        return expected_token

    client.auth_db.lookup_token = mocked_lookup_token
    
    with client.test_client():
        with client.test_request_context(headers=headers_with_token) as client:
            monkeypatch.setattr(Authentication, "decode_token", mocked_decode_token)
            yield client


@pytest.fixture(params=[
    ["lead"],
    ["lead", "analyst"],
    ["analyst"]
])
def request_non_admin_token(request, client, headers_with_token, expected_token, monkeypatch):
    expected_token.roles = request.param

    def mocked_decode_token(self, token):
        return expected_token

    def mocked_lookup_token(token):
        return expected_token

    client.auth_db.lookup_token = mocked_lookup_token

    with client.test_client():
        with client.test_request_context(headers=headers_with_token) as client:
            monkeypatch.setattr(Authentication, "decode_token", mocked_decode_token)
            yield client


@pytest.fixture(params=[
    ["admin"],
    ["admin", "lead"],
    ["admin", "lead", "analyst"],
    ["admin", "analyst"],
    ["lead"],
    ["lead", "analyst"],
    ["analyst"],
    []
])
def request_any_role_token(request, client, headers_with_token, expected_token, monkeypatch):
    expected_token.roles = request.param

    def mocked_decode_token(self, token):
        return expected_token

    def mocked_lookup_token(token):
        return expected_token

    client.auth_db.lookup_token = mocked_lookup_token

    with client.test_client():
        with client.test_request_context(headers=headers_with_token) as client:
            monkeypatch.setattr(Authentication, "decode_token", mocked_decode_token)
            yield client


@pytest.fixture(params=[
    ["admin"],
    ["admin", "lead"],
    ["admin", "analyst"],
    ["lead"],
    ["lead", "analyst"],
    ["analyst"],
    []
])
def request_not_all_roles_token(request, client, headers_with_token, expected_token, monkeypatch):
    expected_token.roles = request.param

    def mocked_decode_token(self, token):
        return expected_token

    def mocked_lookup_token(token):
        return expected_token

    client.auth_db.lookup_token = mocked_lookup_token

    with client.test_client():
        with client.test_request_context(headers=headers_with_token) as client:
            monkeypatch.setattr(Authentication, "decode_token", mocked_decode_token)
            yield client


@pytest.fixture
def request_all_roles_token(client, headers_with_token, expected_token, monkeypatch):
    expected_token.roles = ["admin", "lead", "analyst"]

    def mocked_decode_token(self, token):
        return expected_token

    def mocked_lookup_token(token):
        return expected_token

    client.auth_db.lookup_token = mocked_lookup_token

    with client.test_client():
        with client.test_request_context(headers=headers_with_token) as client:
            monkeypatch.setattr(Authentication, "decode_token", mocked_decode_token)
            yield client


@pytest.fixture()
def client_without_authdb(auth):
    test_app = Flask("test")
    test_app.config["TESTING"] = True
    test_app.auth_db = None
    test_app.authenticator = auth
    return test_app


@pytest.fixture
def request_with_no_authdb(client_without_authdb, headers_with_token):
    with client_without_authdb.test_client():
        with client_without_authdb.test_request_context(headers=headers_with_token) as client:
            yield client
