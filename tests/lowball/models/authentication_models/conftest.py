from datetime import datetime
from lowball.models.authentication_models import ClientData
import pytest
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


@pytest.fixture(params=[
    ["string", "list", "with", "number", 1],
    ["string", "list", "with", "bool", True],
    ["string", "list", "with", "object", object()],
])
def invalid_roles(request):
    return request.param


@pytest.fixture
def roles():
    return ["lead", "analyst"]


@pytest.fixture(params=[datetime(2020, 1, 1, 0, 0, 0, 0), "2020-01-01 00:00:00"])
def created(request):
    return request.param


@pytest.fixture(params=[datetime(2020, 2, 1, 0, 0, 0, 0), "2020-02-01 00:00:00"])
def expiration(request):
    return request.param


@pytest.fixture
def issued_by():
    return "issuer"


@pytest.fixture
def auth_data_dict(username, roles):
    return {
        "username": username,
        "roles": roles
    }


@pytest.fixture
def token_dict(username, roles, created, expiration, issued_by, token_id):
    return {
        "cid": username,
        "r": roles,
        "cts": datetime.strftime(created, _DATE_FORMAT) if isinstance(created, datetime) else str(created),
        "ets": datetime.strftime(expiration, _DATE_FORMAT) if isinstance(expiration, datetime) else str(expiration),
        "rcid": issued_by,
        "tid": token_id
    }


@pytest.fixture(params=[1, True, object(), [1, 2, 3]])
def not_string(request):
    return request.param


@pytest.fixture(params=["bad_date_string", "1606942066224648", "20200101000000"])
def bad_date_string(request):
    return request.param


@pytest.fixture(params=[1, 1.1, True, object(), {}, []])
def invalid_username(request):
    return request.param


@pytest.fixture
def valid_username():
    return "username"


@pytest.fixture
def user(valid_username, roles):
    return ClientData(client_id=valid_username, roles=roles)


@pytest.fixture
def expected_user_to_dict_return(valid_username, roles):
    return {
        "client_id": valid_username,
        "roles": roles
    }
