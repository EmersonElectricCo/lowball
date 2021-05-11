from copy import deepcopy
from datetime import datetime, timedelta
from unittest.mock import Mock, PropertyMock
from lowball.models.authentication_models.token import Token
import flask
import jwt
import pytest
from lowball.authentication import Authentication
from lowball.builtins import DefaultAuthDB, DefaultAuthProvider
from lowball.core import Lowball
from lowball.exceptions import InvalidCredentialsException, NotImplementedException
from lowball.models.provider_models.auth_provider import AuthPackage, AuthProvider, CreateClientPackage, \
    ClientRegistrationPackage, SelfUpdateClientPackage, UpdateClientPackage
from lowball.models.provider_models.auth_db import AuthDatabase
from lowball.models.config_models import Config
from lowball.models.authentication_models import ClientData
import json


###################
# Object Fixtures #
###################


####################
# Request Fixtures #
####################
@pytest.fixture(params=["", "{almost,json}", 1, {"client_id": "something", "BLOB": "something"}])
def does_not_match_auth_package_request(request):
    return request.param

@pytest.fixture
def does_not_match_self_register_package_request(does_not_match_auth_package_request):
    return does_not_match_auth_package_request

@pytest.fixture
def does_not_match_self_update_package_request(does_not_match_auth_package_request):
    return does_not_match_auth_package_request

@pytest.fixture
def does_not_match_update_package_request(does_not_match_auth_package_request):
    return does_not_match_auth_package_request

@pytest.fixture()
def success_request(username):
    return {
        "client_id": username,
        "client_secret": "password"
    }

@pytest.fixture
def basic_header(jwt_token):
    return {"Authorization": f"Bearer {jwt_token}"}

@pytest.fixture
def admin1_token1_request_header(token1_admin1, token_secret):
    return {"Authorization": f"Bearer {jwt.encode(token1_admin1.to_dict(), token_secret)}"}

@pytest.fixture
def normal1_token1_request_header(token1_normal1, token_secret):
    return {"Authorization": f"Bearer {jwt.encode(token1_normal1.to_dict(), token_secret)}"}

@pytest.fixture
def normal2_token1_request_header(token1_normal2, token_secret):
    return {"Authorization": f"Bearer {jwt.encode(token1_normal2.to_dict(), token_secret)}"}


@pytest.fixture(params=[0,1,2,3])
def not_authenticated_or_token_expired_header(request, token3_admin1_expired, token3_normal1_expired, token_secret):
    round = request.param
    if round == 0:
        return {}
    elif round == 1:
        return {"Authorization": f"Bearer InvalidToken"}
    elif round == 2:
        return {"Authorization": f"Bearer {jwt.encode(token3_admin1_expired.to_dict(), token_secret)}"}
    elif round == 3:
        return {"Authorization": f"Bearer {jwt.encode(token3_normal1_expired.to_dict(), token_secret)}"}

@pytest.fixture(params=[0,1,2,3])
def non_admin_headers(request, token1_normal1, token2_normal1, token1_normal2, token2_normal2, token_secret):
    fixture_round = request.param
    if fixture_round == 0:
        return {"Authorization": f"Bearer {jwt.encode(token2_normal1.to_dict(), token_secret)}"}
    if fixture_round == 1:
        return {"Authorization": f"Bearer {jwt.encode(token1_normal2.to_dict(), token_secret)}"}
    if fixture_round == 2:
        return {"Authorization": f"Bearer {jwt.encode(token2_normal2.to_dict(), token_secret)}"}
    if fixture_round == 3:
        return {"Authorization": f"Bearer {jwt.encode(token1_normal1.to_dict(), token_secret)}"}

@pytest.fixture(params=[0,1,2,3])
def token_request_rounds(token_secret, token1_normal1, token2_normal1, token1_admin1, token1_admin2, request):
    fixture_round = request.param

    if fixture_round == 0:
        return {"Authorization": f"Bearer {jwt.encode(token1_normal1.to_dict(), token_secret)}"}, token1_normal1
    if fixture_round == 1:
        return {"Authorization": f"Bearer {jwt.encode(token2_normal1.to_dict(), token_secret)}"}, token2_normal1
    if fixture_round == 2:
        return {"Authorization": f"Bearer {jwt.encode(token1_admin1.to_dict(), token_secret)}"}, token1_admin1
    if fixture_round == 3:
        return {"Authorization": f"Bearer {jwt.encode(token1_admin2.to_dict(), token_secret)}"}, token1_admin2


@pytest.fixture(params=[0, 1, 2, 3, 4, 5])
def invalid_update_roles_requests_rounds(request):

    request_round = request.param

    if request_round == 0:
        return {}
    if request_round == 1:
        return "string not json"
    if request_round == 2:
        return {"add": "not a list"}
    if request_round == 3:
        return {"add": [1, 2, 3]}
    if request_round == 4:
        return {"remove": "not a list"}
    if request_round == 5:
        return {"remove": [1, 2, 3]}


@pytest.fixture
def default_token_life():
    return 3600

@pytest.fixture
def max_token_life():
    return 2592000


@pytest.fixture(params=[0, 1, 2])
def admin_client_create_token_success_rounds(request, client_id_normal1, client_id_normal2, token_secret, fake_now,
                                             base_role1, base_role2, admin_role, all_roles, monkeypatch,
                                             token_id, client_id_admin1, max_token_life, default_token_life):

    request_round = request.param

    if request_round == 0:
        body = {
            "client_id": client_id_normal1,
            "roles": all_roles
        }
        test_token = Token(
            cid=client_id_normal1,
            r=all_roles,
            cts=fake_now,
            ets=fake_now + timedelta(seconds=default_token_life),
            rcid=client_id_admin1,
            tid=token_id)
        token_string = jwt.encode(test_token.to_dict(), token_secret)

        monkeypatch.setattr(
            Authentication,
            "create_token",
            Mock(wraps=Authentication.create_token,
                 return_value=(token_string, test_token)
                 ))

        return body, token_string, test_token

    if request_round == 1:
        body = {
            "client_id": client_id_normal2,
            "roles": base_role2,
            "token_life": 120
        }
        test_token = Token(
            cid=client_id_normal2,
            r=base_role2,
            cts=fake_now,
            ets=fake_now + timedelta(seconds=120),
            rcid=client_id_admin1,
            tid=token_id)
        token_string = jwt.encode(test_token.to_dict(), token_secret)

        monkeypatch.setattr(
            Authentication,
            "create_token",
            Mock(wraps=Authentication.create_token,
                 return_value=(token_string, test_token)
                 ))

        return body, token_string, test_token

    if request_round == 2:
        body = {

        }
        test_token = Token(
            cid=client_id_admin1,
            r=[],
            cts=fake_now,
            ets=fake_now + timedelta(seconds=default_token_life),
            rcid=client_id_admin1,
            tid=token_id)
        token_string = jwt.encode(test_token.to_dict(), token_secret)

        monkeypatch.setattr(
            Authentication,
            "create_token",
            Mock(wraps=Authentication.create_token,
                 return_value=(token_string, test_token)
                 ))

        return body, token_string, test_token


@pytest.fixture(params=[0, 1, 2])
def normal_client_create_token_success_rounds(request, client_id_normal1, token_secret, base_role1, fake_now,
                                              monkeypatch, token_id, default_token_life):
    request_round = request.param

    if request_round == 0:
        body = {
            "roles": base_role1
        }
        test_token = Token(
            cid=client_id_normal1,
            r=base_role1,
            cts=fake_now,
            ets=fake_now + timedelta(seconds=default_token_life),
            rcid=client_id_normal1,
            tid=token_id)
        token_string = jwt.encode(test_token.to_dict(), token_secret)

        monkeypatch.setattr(
            Authentication,
            "create_token",
            Mock(wraps=Authentication.create_token,
                 return_value=(token_string, test_token)
                 ))

        return body, token_string, test_token

    if request_round == 1:
        body = {
            "token_life": 120
        }
        test_token = Token(
            cid=client_id_normal1,
            r=[],
            cts=fake_now,
            ets=fake_now + timedelta(seconds=120),
            rcid=client_id_normal1,
            tid=token_id)
        token_string = jwt.encode(test_token.to_dict(), token_secret)

        monkeypatch.setattr(
            Authentication,
            "create_token",
            Mock(wraps=Authentication.create_token,
                 return_value=(token_string, test_token)
                 ))

        return body, token_string, test_token

    if request_round == 2:
        body = {

        }
        test_token = Token(
            cid=client_id_normal1,
            r=[],
            cts=fake_now,
            ets=fake_now + timedelta(seconds=default_token_life),
            rcid=client_id_normal1,
            tid=token_id)
        token_string = jwt.encode(test_token.to_dict(), token_secret)

        monkeypatch.setattr(
            Authentication,
            "create_token",
            Mock(wraps=Authentication.create_token,
                 return_value=(token_string, test_token)
                 ))

        return body, token_string, test_token

@pytest.fixture
def basic_client_data(all_roles, username):
    return ClientData(username, all_roles)


@pytest.fixture(params=[
    0,
    1,
    2,
    3,
    4
])
def admin_list_token_roles_request_response(request, token_db, base_role1, base_role2, admin_role):
    role1 = base_role1[0]
    role2 = base_role2[0]
    adminrole = admin_role[0]
    queries = [
        f"?roles={role1}",
        f"?roles={role2}",
        f"?roles={adminrole}",
        f"?roles={role1}&roles={role2}",
        f"?roles={adminrole}&roles={role2}"
    ]

    request_round = request.param
    if request_round == 0:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if role1 in token.roles]
        return query, expected_response
    if request_round == 1:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if role2 in token.roles]
        return query, expected_response

    if request_round == 2:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if adminrole in token.roles]
        return query, expected_response

    if request_round == 3:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if role1 in token.roles or role2 in token.roles]
        return query, expected_response

    if request_round == 4:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if adminrole in token.roles or role2 in token.roles]
        return query, expected_response

@pytest.fixture(params=[
    0,
    1,
    2,
    3
])
def admin_list_token_client_request_response(request, token_db, client_id_normal1, client_id_admin1, client_id_normal2):
    queries = [
        f"?client_ids={client_id_normal1}",
        f"?client_ids={client_id_normal2}",
        f"?client_ids={client_id_normal1}&client_ids={client_id_admin1}",
        f"?client_ids={client_id_normal2}&client_ids={client_id_normal1}&client_ids={client_id_admin1}"
    ]
    request_round = request.param
    if request_round == 0:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if
                             token.client_id == client_id_normal1]
        return query, expected_response
    if request_round == 1:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if
                             token.client_id == client_id_normal2]
        return query, expected_response

    if request_round == 2:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if
                             token.client_id == client_id_normal1 or token.client_id == client_id_admin1]
        return query, expected_response

    if request_round == 3:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if
                             token.client_id == client_id_normal1 or token.client_id == client_id_admin1 or token.client_id == client_id_normal2]
        return query, expected_response


@pytest.fixture
def token_db_admin_exclude_expired_response(token_db, fake_now):
    return [token.to_dict() for token in token_db.values() if token.expiration > fake_now]


@pytest.fixture(params=[
    0,
    1,
    2,
])
def admin_list_token_multi_query_request_response(request, token_db, client_id_normal1, base_role1, fake_now):
    role1 = base_role1[0]

    queries = [
        f"?client_ids={client_id_normal1}&roles={role1}",
        f"?client_ids={client_id_normal1}&exclude_expired=yes",
        f"?client_ids={client_id_normal1}&roles={role1}&exclude_expired=yes",
    ]

    request_round = request.param
    if request_round == 0:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if
                             token.client_id == client_id_normal1 and role1 in token.roles]
        return query, expected_response
    if request_round == 1:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if
                             token.client_id == client_id_normal1 and token.expiration > fake_now]
        return query, expected_response

    if request_round == 2:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if
                             token.client_id == client_id_normal1 and token.expiration > fake_now and role1 in token.roles]
        return query, expected_response


@pytest.fixture
def non_admin_client_list_token_expected_response(client_id_normal1, token_db):

    return [token.to_dict() for token in token_db.values() if token.client_id == client_id_normal1]

@pytest.fixture(params=[
    0,
    1,
    2,
    3,
    4
])
def admin_delete_token_roles_request_response(request, token_db, base_role1, base_role2, admin_role):
    role1 = base_role1[0]
    role2 = base_role2[0]
    adminrole = admin_role[0]
    queries = [
        f"?roles={role1}",
        f"?roles={role2}",
        f"?roles={adminrole}",
        f"?roles={role1}&roles={role2}",
        f"?roles={adminrole}&roles={role2}"
    ]

    request_round = request.param
    if request_round == 0:
        query = queries[request_round]
        expected_response = [token for token in token_db.values() if role1 in token.roles]
        return query, expected_response
    if request_round == 1:
        query = queries[request_round]
        expected_response = [token for token in token_db.values() if role2 in token.roles]
        return query, expected_response

    if request_round == 2:
        query = queries[request_round]
        expected_response = [token for token in token_db.values() if adminrole in token.roles]
        return query, expected_response

    if request_round == 3:
        query = queries[request_round]
        expected_response = [token for token in token_db.values() if role1 in token.roles or role2 in token.roles]
        return query, expected_response

    if request_round == 4:
        query = queries[request_round]
        expected_response = [token for token in token_db.values() if adminrole in token.roles or role2 in token.roles]
        return query, expected_response


@pytest.fixture(params=[
    0,
    1,
    2,
    3
])
def admin_delete_token_client_request_response(request, token_db, client_id_normal1, client_id_admin1,
                                               client_id_normal2):
    queries = [
        f"?client_ids={client_id_normal1}",
        f"?client_ids={client_id_normal2}",
        f"?client_ids={client_id_normal1}&client_ids={client_id_admin1}",
        f"?client_ids={client_id_normal2}&client_ids={client_id_normal1}&client_ids={client_id_admin1}"
    ]
    request_round = request.param
    if request_round == 0:
        query = queries[request_round]
        expected_response = [token for token in token_db.values() if
                             token.client_id == client_id_normal1]
        return query, expected_response
    if request_round == 1:
        query = queries[request_round]
        expected_response = [token for token in token_db.values() if
                             token.client_id == client_id_normal2]
        return query, expected_response

    if request_round == 2:
        query = queries[request_round]
        expected_response = [token for token in token_db.values() if
                             token.client_id == client_id_normal1 or token.client_id == client_id_admin1]
        return query, expected_response

    if request_round == 3:
        query = queries[request_round]
        expected_response = [token for token in token_db.values() if
                             token.client_id == client_id_normal1 or token.client_id == client_id_admin1 or token.client_id == client_id_normal2]
        return query, expected_response


@pytest.fixture()
def admin_delete_token_multi_query_request_response(token_db, client_id_normal1, base_role1, fake_now):
    role1 = base_role1[0]

    query = f"?client_ids={client_id_normal1}&roles={role1}"

    expected_response = [token for token in token_db.values() if
                         token.client_id == client_id_normal1 and role1 in token.roles]
    return query, expected_response


@pytest.fixture(params=[
    0,
    1,
    2
])
def non_admin_client_list_token_expected_response_with_queries(client_id_normal1, fake_now,
                                                                  base_role1, base_role2, request, token_db):
    role1 = base_role1[0]
    role2 = base_role2[0]

    queries = [
        f"?roles={role1}",
        f"?roles={role1}&exclude_expired=yes",
        f"?roles={role2}"
    ]
    request_round = request.param
    if request_round == 0:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if
                             token.client_id == client_id_normal1 and role1 in token.roles]
        return query, expected_response
    if request_round == 1:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if
                             token.client_id == client_id_normal1 and token.expiration > fake_now]
        return query, expected_response

    if request_round == 2:
        query = queries[request_round]
        expected_response = [token.to_dict() for token in token_db.values() if
                             token.client_id == client_id_normal1 and role2 in token.roles]
        return query, expected_response

@pytest.fixture(params=[
    "tooshort",
    "toolongtobeatokenid",
    "goodlengthbut$$!",
    "NUMBER4TIME!RUN!"
])
def invalid_token_ids(request):
    return request.param


@pytest.fixture(params=[
    0,
    1,
    2
])
def expected_lookup_token_response_for_admin(request, token1_admin1, token2_admin2, token3_normal1_expired):
    request_round = request.param
    if request_round == 0:
        return token1_admin1.token_id, token1_admin1.to_dict()
    if request_round == 1:
        return token2_admin2.token_id, token2_admin2.to_dict()
    if request_round == 2:
        return token3_normal1_expired.token_id, token3_normal1_expired.to_dict()


@pytest.fixture(params=[
    0,
    1,
    2
])
def normal1_token_ids_request_response(request, token1_normal1, token2_normal1, token3_normal1_expired):

    request_round = request.param
    if request_round == 0:
        return token1_normal1.token_id, token1_normal1.to_dict()
    if request_round == 1:
        return token2_normal1.token_id, token2_normal1.to_dict()
    if request_round == 2:
        return token3_normal1_expired.token_id, token3_normal1_expired.to_dict()

@pytest.fixture(params=[0,1])
def get_client_request_response_rounds(request, admin1_token1_request_header,
                                       normal1_token1_request_header, client_data_normal1, client_data_admin1,
                                       client_id_admin1, client_id_normal1
                                       ):

    request_round = request.param

    if request_round == 0:
        return admin1_token1_request_header, client_id_admin1, client_data_admin1.to_dict()
    if request_round == 1:
        return admin1_token1_request_header, client_id_normal1, client_data_normal1.to_dict()

@pytest.fixture(params=[0,1])
def get_current_client_request_response_rounds(request, admin1_token1_request_header,
                                       normal1_token1_request_header, client_data_normal1, client_data_admin1,
                                       client_id_admin1, client_id_normal1
                                       ):

    request_round = request.param

    if request_round == 0:
        return admin1_token1_request_header, client_id_admin1, client_data_admin1.to_dict()
    if request_round == 1:
        return normal1_token1_request_header, client_id_normal1, client_data_normal1.to_dict()

@pytest.fixture(params=[0, 1, 2])
def get_clients_request_response_rounds(request, client_data_admin1, client_data_normal1, admin_role, base_role1):
    request_round = request.param
    admin_role_value = admin_role[0]
    role1 = base_role1[0]
    if request_round == 0:
        query = f"?roles={admin_role_value}"
        expected_client_data = [client_data_admin1]
        return query, expected_client_data
    if request_round == 1:
        query = f"?roles={role1}"
        expected_client_data = [client_data_normal1]
        return query, expected_client_data

    if request_round == 2:
        query = f"?roles={role1}&roles={admin_role_value}"
        expected_client_data = [client_data_admin1, client_data_normal1]
        return query, expected_client_data




@pytest.fixture(params=[0, 1, 2, 3])
def create_token_request_bad_token_life_rounds(request):
    request_round = request.param
    if request_round == 0:
        return {
            "token_life": "not an integer",
            "client_id": "test",
            "roles": []
        }
    if request_round == 1:
        return {
            "token_life": 8,
            "client_id": "test",
            "roles": []
        }
    if request_round == 2:
        return {
            "token_life": 999999999999999,
            "client_id": "test",
            "roles": []
        }
    if request_round == 3:
        return {
            "token_life": True,
            "client_id": "test",
            "roles": []
        }




###################
# Client Fixtures #
###################

@pytest.fixture
def test_app_config(token_secret, default_token_life, max_token_life):

    config = Config()
    config.authentication.token_secret = token_secret
    config.authentication.default_token_life = default_token_life
    config.authentication.max_token_life = max_token_life
    return config


@pytest.fixture
def lowball_app(test_app_config):
    app = Lowball(response_class=flask.Response, logging_handler=None, config=test_app_config)
    app.config["TESTING"] = True
    app.logger._log = Mock()

    with app.test_client() as client:
        yield client


@pytest.fixture
def lowball_app_mock_providers(test_authdb_base, test_authprovider_base, test_app_config):
    app = Lowball(response_class=flask.Response, logging_handler=None,
                  auth_provider=test_authprovider_base, auth_database=test_authdb_base,
                  config=test_app_config)
    app.config["TESTING"] = True
    app.logger._log = Mock()

    with app.test_client() as client:
        yield client


@pytest.fixture
def lowball_app_no_providers(test_app_config):
    app = Lowball(response_class=flask.Response,
                  logging_handler=None, auth_provider=None,
                  auth_database=None, config=test_app_config)
    app.config["TESTING"] = True
    app.logger._log = Mock()

    with app.test_client() as client:
        yield client


@pytest.fixture
def lowball_app_no_db(test_authprovider_base, test_app_config):
    app = Lowball(response_class=flask.Response, logging_handler=None, auth_database=None,
                  auth_provider=test_authprovider_base, config=test_app_config)
    app.config["TESTING"] = True
    app.logger._log = Mock()

    with app.test_client() as client:
        yield client


@pytest.fixture
def lowball_app_no_auth_provider(test_authdb_base, test_app_config):
    app = Lowball(response_class=flask.Response, logging_handler=None, auth_provider=None,
                  auth_database=test_authdb_base, config=test_app_config)
    app.config["TESTING"] = True
    app.logger._log = Mock()

    with app.test_client() as client:
        yield client

##############################
# Expected Response Fixtures #
##############################

@pytest.fixture
def expected_login_error_response():
    return "400 Bad Request: The Authentication Request Did Not Supply The Required Data"

@pytest.fixture
def expected_bad_package_data_error_response():
    return "400 Bad Request: The Request Did Not Supply The Required Data for the Auth Provider"

@pytest.fixture
def expected_no_auth_provider_error_response():
    return "503 Service Unavailable: No Authentication Provider Present"

@pytest.fixture
def expected_inadequate_roles_exception_response():
    return "401 Unauthorized: Current Token Has Inadequate Roles for Requested Action"


@pytest.fixture
def expected_non_list_returned_from_list_tokens_response():
    return "500 Internal Server Error: auth_db.list_tokens did not return a list as expected"


@pytest.fixture
def expected_non_token_in_token_list_response():
    return "500 Internal Server Error: auth_db.list_tokens returned a list that included a non-Token object"


@pytest.fixture
def expected_nonexistent_token_response():
    return "404 Not Found: Specified token not found"


@pytest.fixture
def expected_no_auth_db_response():
    return "503 Service Unavailable: No authentication database configured for this application"


@pytest.fixture
def expected_bad_token_life_response():
    return "token_life must be a positive integer greater than 10 and less than 2592000"

###############
# Basic Mocks #
###############

@pytest.fixture(params=[
    TypeError("TESTEXCEPTION"),
    ValueError("TESTEXCEPTION"),
    Exception("TESTEXCEPTION")
])
def mock_initialized_exception(monkeypatch, request):
    monkeypatch.setattr(TestAuthProvider, "initialized", Mock(side_effect=request.param))


@pytest.fixture(params=[1, 1.1, object(), [], {}, "string"])
def mock_initialized_non_bool(monkeypatch, request):
    monkeypatch.setattr(TestAuthProvider, "initialized", request.param)


@pytest.fixture(params=[True, False])
def mock_initialized_bool(monkeypatch, request):
    monkeypatch.setattr(TestAuthProvider, "initialized", request.param)
    return request.param

########################
# Authentication Mocks #
########################
@pytest.fixture
def mock_create_token(monkeypatch, token, jwt_token):

    monkeypatch.setattr(Authentication, "create_token", Mock(return_value=(jwt_token, token)))

@pytest.fixture
def mock_decode_token(monkeypatch, token):
    monkeypatch.setattr(Authentication, "decode_token", Mock(return_value=token))

################
# AuthDB Mocks #
################

@pytest.fixture
def token_db(token1_normal1, token2_normal1, token2_normal2, token1_normal2,
                             token1_admin2, token1_admin1, token2_admin1, token2_admin2, token,
                             token3_admin1_expired, token3_normal1_expired, token3_normal2_expired,
                             token3_admin2_expired):
    return {
            token.token_id: token,
            token1_normal1.token_id: token1_normal1,
            token2_normal1.token_id: token2_normal1,
            token2_normal2.token_id: token2_normal2,
            token1_normal2.token_id: token1_normal2,
            token1_admin2.token_id: token1_admin2,
            token1_admin1.token_id: token1_admin1,
            token2_admin1.token_id: token2_admin1,
            token2_admin2.token_id: token2_admin2,
            token3_admin1_expired.token_id: token3_admin1_expired,
            token3_normal1_expired.token_id: token3_normal1_expired,
            token3_normal2_expired.token_id: token3_normal2_expired,
            token3_admin2_expired.token_id: token3_admin2_expired,
        }

class TestAuthDB(AuthDatabase):



    def add_token(self, token_object):
        pass

    def lookup_token(self, token_id):

        pass

    def list_tokens(self):

        pass

    def list_tokens_by_role(self, role):
        pass

    def list_tokens_by_client_id(self, client_id):

        pass

    def cleanup_tokens(self):

        pass

    def revoke_all(self):
        pass

    def revoke_token(self, token_id):
        pass

@pytest.fixture
def test_authdb_base():

    return TestAuthDB

@pytest.fixture
def mock_lookup_token(monkeypatch, token):
    monkeypatch.setattr(TestAuthDB, "lookup_token", Mock(return_value=token))

@pytest.fixture
def mock_revoke_token(monkeypatch, token):
    monkeypatch.setattr(TestAuthDB, "revoke_token", Mock())

@pytest.fixture
def mock_lookup_token_filled(monkeypatch, token_db):
    def lookup_token(token_id):

        return token_db.get(token_id)

    monkeypatch.setattr(TestAuthDB, "lookup_token", Mock(wraps=lookup_token))

@pytest.fixture
def mock_list_tokens_filled(monkeypatch, token_db):
    def list_tokens():
        return list(token_db.values())

    monkeypatch.setattr(TestAuthDB, "list_tokens", Mock(wraps=list_tokens))

@pytest.fixture
def mock_list_tokens_by_role(monkeypatch, token_db):
    def list_tokens_by_role(role):

        return [token for token in list(token_db.values()) if role in token.roles]

    monkeypatch.setattr(TestAuthDB, "list_tokens_by_role", Mock(wraps=list_tokens_by_role))

@pytest.fixture
def mock_list_tokens_by_client_id(monkeypatch, token_db):

    def list_tokens_by_client_id(client_id):
        return [token for token in list(token_db.values()) if client_id == token.client_id]

    monkeypatch.setattr(TestAuthDB, "list_tokens_by_client_id", Mock(wraps=list_tokens_by_client_id))

@pytest.fixture(params=[0, 1])
def mock_list_tokens_returns_bad_values(monkeypatch, request):
    request_round = request.param
    if request_round == 0:

        monkeypatch.setattr(TestAuthDB, "list_tokens", Mock(return_value=["not", "tokens"]))
        monkeypatch.setattr(TestAuthDB, "list_tokens_by_client_id", Mock(return_value=["not", "tokens"]))
    if request_round == 1:
        monkeypatch.setattr(TestAuthDB, "list_tokens", Mock(return_value="not list"))
        monkeypatch.setattr(TestAuthDB, "list_tokens_by_client_id", Mock(return_value="not list"))

@pytest.fixture
def mock_revoke_token(monkeypatch):
    monkeypatch.setattr(TestAuthDB, "revoke_token", Mock())

@pytest.fixture
def mock_revoke_all(monkeypatch):

    monkeypatch.setattr(TestAuthDB, "revoke_all", Mock())

@pytest.fixture
def mock_cleanup_tokens(monkeypatch):
    monkeypatch.setattr(TestAuthDB, "cleanup_tokens", Mock())

@pytest.fixture
def mock_add_token(monkeypatch):
    monkeypatch.setattr(TestAuthDB, "add_token", Mock())


#######################
# Auth Provider Mocks #
#######################

class TestAuthProvider(AuthProvider):

    def authenticate(self, auth_package):

        pass

    @property
    def auth_package_class(self):
        return None

@pytest.fixture
def client_data_normal1(client_id_normal1, base_role1):
    return ClientData(client_id=client_id_normal1, roles=base_role1)

@pytest.fixture
def client_data_admin1(client_id_admin1, admin_role):
    return ClientData(client_id=client_id_admin1, roles=admin_role)

@pytest.fixture
def client_db(client_id_normal1, client_id_admin1, client_data_normal1, client_data_admin1):

    return {
        client_id_normal1: client_data_normal1,
        client_id_admin1: client_data_admin1
    }

@pytest.fixture
def mock_get_client_filled(monkeypatch, client_db):

    def get_client(client_id):

        return client_db.get(client_id)

    monkeypatch.setattr(TestAuthProvider, "get_client", Mock(wraps=get_client))

@pytest.fixture
def mock_get_client_not_implemented(monkeypatch):

    monkeypatch.setattr(TestAuthProvider, "get_client", Mock(side_effect=NotImplementedException("get_client")))

@pytest.fixture
def mock_list_clients_filled(monkeypatch, client_db):

    def list_clients():

        return list(client_db.values())

    monkeypatch.setattr(TestAuthProvider, "list_clients", Mock(wraps=list_clients))

@pytest.fixture(params=[0, 1])
def mock_list_clients_returns_bad_values(monkeypatch, request):
    request_round = request.param
    if request_round == 0:

        monkeypatch.setattr(TestAuthProvider, "list_clients", Mock(return_value=["not", "client_data"]))
    if request_round == 1:
        monkeypatch.setattr(TestAuthProvider, "list_clients", Mock(return_value="not list"))

@pytest.fixture
def mock_delete_roles(monkeypatch):

    monkeypatch.setattr(TestAuthProvider, "delete_roles", Mock())

@pytest.fixture
def mock_add_roles(monkeypatch):

    monkeypatch.setattr(TestAuthProvider, "add_roles", Mock())

@pytest.fixture
def mock_get_client_not_found(monkeypatch):
    monkeypatch.setattr(TestAuthProvider, "get_client", Mock(return_value=None))

@pytest.fixture
def mock_get_client_found(monkeypatch, basic_client_data):
    monkeypatch.setattr(TestAuthProvider, "get_client", Mock(return_value=basic_client_data))

@pytest.fixture
def test_authprovider_base():

    return TestAuthProvider

@pytest.fixture
def mock_auth_package_class(monkeypatch):

    class TestAuthPackage(AuthPackage):
        def __init__(self, client_id, client_secret):
            self.client_id = client_id
            self.client_secret = client_secret

    monkeypatch.setattr(TestAuthProvider, "auth_package_class", PropertyMock(return_value=TestAuthPackage))

@pytest.fixture
def mock_self_register_class(monkeypatch):
    class TestSelfRegisterPackage(ClientRegistrationPackage):
        def __init__(self, client_id, client_secret):
            self.client_id = client_id
            self.client_secret = client_secret
    monkeypatch.setattr(TestAuthProvider, "client_registration_package_class", PropertyMock(return_value=TestSelfRegisterPackage))

@pytest.fixture
def mock_self_update_class(monkeypatch):
    class TestSelfUpdateClientPackage(SelfUpdateClientPackage):
        def __init__(self, client_id, client_secret):
            self.client_id = client_id
            self.client_secret = client_secret
    monkeypatch.setattr(TestAuthProvider, "self_update_client_package_class", PropertyMock(return_value=TestSelfUpdateClientPackage))


@pytest.fixture
def mock_update_client_class(monkeypatch):
    class TestUpdateClientPackage(UpdateClientPackage):
        def __init__(self, client_id, client_secret):

            self.client_id = client_id
            self.client_secret = client_secret

    monkeypatch.setattr(TestAuthProvider, "update_client_package_class",
                            PropertyMock(return_value=TestUpdateClientPackage))

@pytest.fixture
def mock_create_client_class(monkeypatch):
    class TestCreateClientPackage(CreateClientPackage):
        def __init__(self, client_id, client_secret):

            self.client_id = client_id
            self.client_secret = client_secret

    monkeypatch.setattr(TestAuthProvider, "create_client_package_class",
                            PropertyMock(return_value=TestCreateClientPackage))


@pytest.fixture
def mock_delete_client_simple(monkeypatch):
    monkeypatch.setattr(TestAuthProvider, "delete_client", Mock())

@pytest.fixture
def mock_enable_client_simple(monkeypatch):
    monkeypatch.setattr(TestAuthProvider, "enable_client", Mock())

@pytest.fixture
def mock_disable_client_simple(monkeypatch):
    monkeypatch.setattr(TestAuthProvider, "disable_client", Mock())

@pytest.fixture
def mock_add_and_delete_roles_simple(monkeypatch):

    monkeypatch.setattr(TestAuthProvider, "add_roles", Mock())
    monkeypatch.setattr(TestAuthProvider, "delete_roles", Mock())


@pytest.fixture(params=[0, 1, 2])
def mock_self_register_rounds(request, monkeypatch, basic_client_data):
    if request.param == 0:
        monkeypatch.setattr(TestAuthProvider, "client_self_register", Mock(return_value=basic_client_data))
    elif request.param == 1:
        monkeypatch.setattr(TestAuthProvider, "client_self_register", Mock(return_value=basic_client_data.to_dict()))

    elif request.param == 2:
        monkeypatch.setattr(TestAuthProvider, "client_self_register", Mock(return_value=json.dumps(basic_client_data.to_dict())))

@pytest.fixture(params=[0, 1, 2])
def mock_self_update_rounds(request, monkeypatch, basic_client_data):
    if request.param == 0:
        monkeypatch.setattr(TestAuthProvider, "client_self_update", Mock(return_value=basic_client_data))
    elif request.param == 1:
        monkeypatch.setattr(TestAuthProvider, "client_self_update", Mock(return_value=basic_client_data.to_dict()))

    elif request.param == 2:
        monkeypatch.setattr(TestAuthProvider, "client_self_update", Mock(return_value=json.dumps(basic_client_data.to_dict())))

@pytest.fixture(params=[0, 1, 2])
def mock_update_client_rounds(request, monkeypatch, basic_client_data):
    if request.param == 0:
        monkeypatch.setattr(TestAuthProvider, "update_client", Mock(return_value=basic_client_data))
    elif request.param == 1:
        monkeypatch.setattr(TestAuthProvider, "update_client", Mock(return_value=basic_client_data.to_dict()))

    elif request.param == 2:
        monkeypatch.setattr(TestAuthProvider, "update_client", Mock(return_value=json.dumps(basic_client_data.to_dict())))

@pytest.fixture(params=[0, 1, 2])
def mock_create_client_rounds(request, monkeypatch, basic_client_data):
    if request.param == 0:
        monkeypatch.setattr(TestAuthProvider, "create_client", Mock(return_value=basic_client_data))
    elif request.param == 1:
        monkeypatch.setattr(TestAuthProvider, "create_client", Mock(return_value=basic_client_data.to_dict()))

    elif request.param == 2:
        monkeypatch.setattr(TestAuthProvider, "create_client", Mock(return_value=json.dumps(basic_client_data.to_dict())))



@pytest.fixture
def mock_authenticate_basic(monkeypatch, username, all_roles):

    monkeypatch.setattr(TestAuthProvider, "authenticate", Mock(return_value=ClientData(username, roles=all_roles)))






