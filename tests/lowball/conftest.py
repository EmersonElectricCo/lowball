import datetime
from pathlib import Path
from unittest.mock import Mock, PropertyMock
from copy import deepcopy
import pytest
from flask import Flask, template_rendered, before_render_template, request_started, request_finished, \
    request_tearing_down, got_request_exception, appcontext_tearing_down, appcontext_popped, appcontext_pushed, \
    message_flashed
from flask.signals import Namespace
from werkzeug.datastructures import Headers
import jwt
from lowball import Lowball
from lowball.authentication.authentication import Authentication
from lowball.models.authentication_models import Token, ClientData
from lowball.models.config_models import Config, MetaConfig, AuthenticationConfig
from lowball.models.provider_models import AuthDatabase, AuthProvider
from lowball.models.provider_models.auth_provider import (
    AuthPackage,
    ClientRegistrationPackage,
    UpdateClientPackage,
    SelfUpdateClientPackage,
    CreateClientPackage
)

FAKE_NOW = datetime.datetime(2020, 1, 1, 0, 0, 0, 0)


@pytest.fixture
def fake_now():
    return FAKE_NOW

@pytest.fixture
def expired_time():
    return datetime.datetime(2019, 1, 1, 0, 0, 0, 0)

@pytest.fixture
def token_secret():
    return "supersecrettokensecret"

@pytest.fixture
def bad_token_secret():
    return "notactuallybadbutdifferent"

@pytest.fixture(params=[1, True, {}, object()])
def not_datetime(request):
    return request.param


@pytest.fixture(params=[{}, [], object(), 0, 1.1, True])
def not_string(request):
    return request.param


@pytest.fixture
def token_id():
    return "thesimpletokenid"


@pytest.fixture
def expected_token(token_id):
    return Token(
        cid="username",
        r=[],
        cts=datetime.datetime(2019, 11, 1),
        ets=datetime.datetime(2020, 12, 1),
        rcid="another_user",
        tid=token_id
    )

@pytest.fixture
def expired_token(token_id):
    return Token(
        cid="username",
        r=[],
        cts=datetime.datetime(2019, 11, 1),
        ets=datetime.datetime(2019, 12, 1),
        rcid="another_user",
        tid=token_id
    )

@pytest.fixture
def expected_token_string(expected_token, token_secret):

    return jwt.encode(expected_token.to_dict(), token_secret, algorithm="HS256")

@pytest.fixture
def expired_token_string(expired_token, token_secret):
    return jwt.encode(expired_token.to_dict(), token_secret, algorithm="HS256")

@pytest.fixture
def invalid_expected_token_string(expected_token, bad_token_secret):
    return jwt.encode(expected_token.to_dict(), bad_token_secret, algorithm="HS256")


@pytest.fixture
def auth_config(token_secret):
    return AuthenticationConfig(
        default_token_life=1800,
        max_token_life=31536000,
        token_secret=token_secret
    )


@pytest.fixture
def mock_auth_db():
    class MockAuthDB(AuthDatabase):
        def add_token(self, token_object):
            pass

        def lookup_token(self, token_id):
            pass  # TODO this is what needs to be mocked, a couple different cases

        def revoke_token(self, token_id):
            pass

        def list_tokens(self):
            pass

        def list_tokens_by_client_id(self, client_id):
            pass

        def list_tokens_by_role(self, role):
            pass

        def cleanup_tokens(self):
            pass

        def revoke_all(self):
            pass

    return MockAuthDB()


@pytest.fixture
def auth_package_test_class():
    class TestAuthPackage(AuthPackage):

        def __init__(self, client_id, client_secret, **kwargs):
            self.client_id = client_id
            self.client_secret = client_secret
            AuthPackage.__init__(self)

    return TestAuthPackage


@pytest.fixture
def client_registration_package_test_class():
    class TestClientRegistrationPackage(ClientRegistrationPackage):

        def __init__(self, client_id, client_info, **kwargs):
            self.client_id = client_id
            self.client_info = client_info
            ClientRegistrationPackage.__init__(self)

    return TestClientRegistrationPackage

@pytest.fixture
def client_update_package_test_calss():
    class TestClientUpdatePackage(UpdateClientPackage):

        def __init__(self, client_info1, client_info2, **kwargs):
            self.client_info1 = client_info1
            self.client_info2 = client_info2
            UpdateClientPackage.__init__(self)

    return TestClientUpdatePackage

@pytest.fixture
def client_self_update_package_test_calss():
    class TestClientSelfUpdatePackage(SelfUpdateClientPackage):

        def __init__(self, client_info1, client_info2, **kwargs):
            self.client_info1 = client_info1
            self.client_info2 = client_info2
            SelfUpdateClientPackage.__init__(self)

    return TestClientSelfUpdatePackage


@pytest.fixture
def mock_auth_provider_base(auth_package_test_class, client_data):
    class MockAuthProvider(AuthProvider):

        @property
        def auth_package_class(self):
            return auth_package_test_class

        def authenticate(self, auth_package):

            return client_data

    return MockAuthProvider()


@pytest.fixture
def auth(auth_config):
    return Authentication(config=auth_config)


@pytest.fixture(autouse=True)
def client(mock_auth_db, auth):
    test_app = Flask("test")
    test_app.config["TESTING"] = True
    test_app.auth_db = mock_auth_db
    test_app.authenticator = auth
    return test_app


@pytest.fixture(params=[1, [1, 2, 3], ("tuple",), {1, 2, 3}, {}])
def not_pathlike(request):
    return request.param


@pytest.fixture(autouse=True)
def patched_utcnow(monkeypatch):
    class MockedDatetime(datetime.datetime):
        @classmethod
        def utcnow(cls):
            return FAKE_NOW

    monkeypatch.setattr(datetime, "datetime", MockedDatetime)


@pytest.fixture(params=[1800, "1800"])
def default_token_life(request):
    return request.param


@pytest.fixture(params=[1800, "1800"])
def max_token_life(request):
    return request.param


@pytest.fixture
def authentication_config(default_token_life, max_token_life, token_secret):
    return AuthenticationConfig(
        default_token_life=default_token_life,
        max_token_life=max_token_life,
        token_secret=token_secret
    )


@pytest.fixture
def meta_config():
    return MetaConfig(name="APP_NAME", base_route="/base/route", description="description", tags=["tag", "list"])


@pytest.fixture
def lowball_config(meta_config, authentication_config):
    logging_config = {
        "filename": "lowball.log",
        "formatter": {
            "date_format": "%Y-%m-%d %H:%M:%S.%fUTC"
        }
    }
    return Config(meta=meta_config, authentication=authentication_config, logging=logging_config)


@pytest.fixture
def mocked_lowball_init(monkeypatch):
    monkeypatch.setattr(Flask, "register_blueprint", Mock())
    monkeypatch.setattr(Flask, "register_error_handler", Mock())
    monkeypatch.setattr(Lowball, "register_request_finished_handler", Mock())


@pytest.fixture
def mocked_mkdir(monkeypatch):
    monkeypatch.setattr(Path, "mkdir", Mock())


@pytest.fixture
def lowball_app(lowball_config, mocked_mkdir):
    return Lowball(config=lowball_config)


@pytest.fixture
def signal_subscriber():
    def subscriber(sender, **extra):
        pass

    return subscriber


@pytest.fixture
def other_signal_subscriber():
    def other_subscriber(sender, **extra):
        pass

    return other_subscriber


@pytest.fixture
def mocked_signals(monkeypatch):
    monkeypatch.setattr(template_rendered, "connect", Mock())
    monkeypatch.setattr(before_render_template, "connect", Mock())
    monkeypatch.setattr(request_started, "connect", Mock())
    monkeypatch.setattr(request_finished, "connect", Mock())
    monkeypatch.setattr(got_request_exception, "connect", Mock())
    monkeypatch.setattr(request_tearing_down, "connect", Mock())
    monkeypatch.setattr(appcontext_tearing_down, "connect", Mock())
    monkeypatch.setattr(appcontext_pushed, "connect", Mock())
    monkeypatch.setattr(appcontext_popped, "connect", Mock())
    monkeypatch.setattr(message_flashed, "connect", Mock())


@pytest.fixture
def custom_signal():
    ns = Namespace()
    custom_sig = ns.signal("custom_signal")
    custom_sig.connect = Mock()

    return custom_sig

@pytest.fixture
def headers():
    return Headers()


@pytest.fixture
def headers_with_token(headers, jwt_token):
    headers.add("Authorization", f"Bearer {jwt_token}")
    return headers


@pytest.fixture(params=[
    "Nothing about this is correct",
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ2ZXJzaW9uIjoiMSIsInVzZXJuYW1lIjoidXNlcm5hbWUxIiwicm9sZXMiOlsiYWRtaW4iLCJsZWFkIiwiYW5hbHlzdCJdLCJjcmVhdGVkIjoiMjAyMC0wMS0wMSAwMDowMDowMCIsImV4cGlyYXRpb24iOiIyMDIwLTAxLTAxIDAwOjMwOjAwIiwiaXNzdWVkX2J5IjoidXNlcm5hbWUxIiwidG9rZW5faWQiOiI0NmY5NjQzNS04N2ZhLTQzNjMtYWM1Ny1lZmRjNzI2NzhiMzcifQ.Dj92CngpXF9HZU-czed2qqyOocHnyccTzNt5VKIQN6U",
])
def headers_invalid_auth(request):
    headers = Headers()
    headers.add("Authorization", request.param)
    return headers


@pytest.fixture
def token(token_id, all_roles):
    return Token(
        cid="username",
        r=all_roles,
        cts=datetime.datetime(2020, 1, 1),
        ets=datetime.datetime(2020, 2, 1),
        rcid="username",
        tid=token_id
    )

@pytest.fixture
def jwt_token(token, token_secret):
    return jwt.encode(token.to_dict(), token_secret, algorithm="HS256")

@pytest.fixture
def username():
    return "username"

@pytest.fixture
def admin_role():
    return ["admin"]

@pytest.fixture
def base_role1():
    return ["role1"]

@pytest.fixture
def base_role2():
    return ["role2"]

@pytest.fixture
def base_roles(base_role1, base_role2):
    return base_role1 + base_role2

@pytest.fixture
def all_roles(admin_role, base_roles):
    return admin_role + base_roles

@pytest.fixture(params=[1, 1.1, {}, True, object(), "string"])
def not_list(request):
    return request.param


# TOKEN IDS
@pytest.fixture
def token_id1():
    return "abcdef0123456789"

@pytest.fixture
def token_id2():
    return "bbcdef0123456789"

@pytest.fixture
def token_id3():
    return "cbcdef0123456789"

@pytest.fixture
def token_id4():
    return "dbcdef0123456789"

@pytest.fixture
def token_id5():
    return "ebcdef0123456789"

@pytest.fixture
def token_id6():
    return "fbcdef0123456789"

@pytest.fixture
def token_id7():
    return "gbcdef0123456789"

@pytest.fixture
def token_id8():
    return "hbcdef0123456789"

@pytest.fixture
def token_id9():
    return "ibcdef0123456789"

@pytest.fixture
def token_id10():
    return "jbcdef0123456789"

@pytest.fixture
def token_id11():
    return "kbcdef0123456789"

@pytest.fixture
def token_id12():
    return "lbcdef0123456789"


# CLIENT IDS
@pytest.fixture
def client_id_admin1():
    return "admin1"

@pytest.fixture
def client_id_admin2():
    return "admin2"

@pytest.fixture
def client_id_normal1():
    return "non_admin1"

@pytest.fixture
def client_id_normal2():
    return "non_admin2"

# TOKENS
@pytest.fixture
def token1_admin1(token_id1, client_id_admin1, token, admin_role):
    modified_token = deepcopy(token)
    modified_token.token_id = token_id1
    modified_token.client_id = client_id_admin1
    modified_token.roles = admin_role
    return modified_token

@pytest.fixture
def token2_admin1(token_id2, client_id_admin1, token, all_roles):
    modified_token = deepcopy(token)
    modified_token.token_id = token_id2
    modified_token.client_id = client_id_admin1
    modified_token.roles = all_roles
    return modified_token

@pytest.fixture
def token3_admin1_expired(token_id3, client_id_admin1, token, admin_role, expired_time):
    modified_token = deepcopy(token)
    modified_token.token_id = token_id3
    modified_token.client_id = client_id_admin1
    modified_token.roles = admin_role
    modified_token.expiration = expired_time
    return modified_token

@pytest.fixture
def token1_admin2(token_id4, client_id_admin2, token, admin_role):
    modified_token = deepcopy(token)
    modified_token.token_id = token_id4
    modified_token.client_id = client_id_admin2
    modified_token.roles = admin_role
    return modified_token

@pytest.fixture
def token2_admin2(token_id5, client_id_admin2, token, all_roles):
    modified_token = deepcopy(token)
    modified_token.token_id = token_id5
    modified_token.client_id = client_id_admin2
    modified_token.roles = all_roles
    return modified_token

@pytest.fixture
def token3_admin2_expired(token_id6, client_id_admin2, token, admin_role, expired_time):
    modified_token = deepcopy(token)
    modified_token.token_id = token_id6
    modified_token.client_id = client_id_admin2
    modified_token.roles = admin_role
    modified_token.expiration = expired_time
    return modified_token

@pytest.fixture
def token1_normal1(token_id7, client_id_normal1, token, base_role1):
    modified_token = deepcopy(token)
    modified_token.token_id = token_id7
    modified_token.client_id = client_id_normal1
    modified_token.roles = base_role1
    return modified_token

@pytest.fixture
def token2_normal1(token_id8, client_id_normal1, token, base_roles):
    modified_token = deepcopy(token)
    modified_token.token_id = token_id8
    modified_token.client_id = client_id_normal1
    modified_token.roles = base_roles
    return modified_token

@pytest.fixture
def token3_normal1_expired(token_id9, client_id_normal1, token, base_role2, expired_time):
    modified_token = deepcopy(token)
    modified_token.token_id = token_id9
    modified_token.client_id = client_id_normal1
    modified_token.roles = base_role2
    modified_token.expiration = expired_time
    return modified_token

@pytest.fixture
def token1_normal2(token_id10, client_id_normal2, token, base_role2):
    modified_token = deepcopy(token)
    modified_token.token_id = token_id10
    modified_token.client_id = client_id_normal2
    modified_token.roles = base_role2
    return modified_token

@pytest.fixture
def token2_normal2(token_id11, client_id_normal2, token, base_roles):
    modified_token = deepcopy(token)
    modified_token.token_id = token_id11
    modified_token.client_id = client_id_normal2
    modified_token.roles = base_roles
    return modified_token

@pytest.fixture
def token3_normal2_expired(token_id12, client_id_normal2, token, base_role1, expired_time):
    modified_token = deepcopy(token)
    modified_token.token_id = token_id12
    modified_token.client_id = client_id_normal2
    modified_token.roles = base_role1
    modified_token.expiration = expired_time
    return modified_token


@pytest.fixture
def client_data(all_roles):
    return ClientData("username1", roles=all_roles)
