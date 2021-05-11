import builtins
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from unittest.mock import mock_open, Mock

import pytest
from ruamel.yaml import YAML

from lowball.builtins.providers import DefaultAuthDB, DefaultAuthProvider, DefaultAuthPackage
from lowball.models.authentication_models import Token, ClientData
from lowball.models.provider_models.auth_provider import AuthPackage
import json

@pytest.fixture(params=[
    "/opt/lowball/tokens",
    Path("/opt/lowball/tokens")
])
def token_path(request):
    return request.param


@pytest.fixture
def token_file_contents(token):
    return json.dumps(token.to_dict())


@pytest.fixture
def token_file(monkeypatch, token_file_contents):
    mock_file = mock_open(read_data=token_file_contents)
    monkeypatch.setattr(builtins, "open", mock_file)


@pytest.fixture
def corrupted_token_file(monkeypatch, token_file_contents):
    mock_file = mock_open(read_data="Corrupted Data")
    monkeypatch.setattr(builtins, "open", mock_file)


@pytest.fixture
def mock_open_file(monkeypatch, token_file_contents):
    mock_file = mock_open()
    monkeypatch.setattr(builtins, "open", mock_file)
    return mock_file


@pytest.fixture
def mocked_yaml_dump(monkeypatch):
    monkeypatch.setattr(YAML, "dump", Mock())


@pytest.fixture
def mock_nonexistent_path(monkeypatch):
    monkeypatch.setattr(Path, "exists", Mock(return_value=False))


@pytest.fixture
def mock_existent_path(monkeypatch):
    monkeypatch.setattr(Path, "exists", Mock(return_value=True))


@pytest.fixture
def mock_path_unlink(monkeypatch):
    monkeypatch.setattr(Path, "unlink", Mock())


@pytest.fixture
def mock_unlink_non_existent_file(monkeypatch):
    mock = Mock()
    mock.side_effect = FileNotFoundError
    monkeypatch.setattr(Path, "unlink", mock)


@pytest.fixture
def default_auth_db(token_path, mocked_mkdir):
    return DefaultAuthDB(token_path=token_path)


@pytest.fixture
def mock_default_auth_db_internals(monkeypatch, token):
    monkeypatch.setattr(DefaultAuthDB, "_dump_token", Mock(return_value=True))
    monkeypatch.setattr(DefaultAuthDB, "_load_token", Mock(return_value=token))
    monkeypatch.setattr(DefaultAuthDB, "_delete_token", Mock(return_value=True))


@pytest.fixture(params=["token", "token_id"])
def token_identifier(request, token_id, token):
    return {"token": token, "token_id": token_id}[request.param]


@pytest.fixture
def mock_internal_load_non_existent_token(monkeypatch):
    monkeypatch.setattr(DefaultAuthDB, "_load_token", Mock(return_value=None))


@pytest.fixture
def mock_internal_revoke_token(monkeypatch):
    monkeypatch.setattr(DefaultAuthDB, "_delete_token", Mock())


@pytest.fixture
def mock_iterdir(monkeypatch, default_auth_db, token_id1, token_id2, token_id3, token_id4, token_id5):
    file_list = [
        default_auth_db.token_path.joinpath(token_id1),
        default_auth_db.token_path.joinpath(token_id2),
        default_auth_db.token_path.joinpath(token_id3),
        default_auth_db.token_path.joinpath(token_id4),
        default_auth_db.token_path.joinpath(token_id5),
    ]
    monkeypatch.setattr(Path, "iterdir", Mock(return_value=iter(file_list)))


@pytest.fixture
def mock_load_multiple_tokens_internal(monkeypatch, token, default_auth_db, token_id3, token_id4):
    def send_back_token(token_id):
        if token_id in [default_auth_db.token_path.joinpath(token_id3),
                        default_auth_db.token_path.joinpath(token_id4)]:
            return None
        else:
            token.token_id = token_id.name
            return token

    monkeypatch.setattr(DefaultAuthDB, "_load_token", Mock(wraps=send_back_token))


@pytest.fixture
def expected_list_tokens(token, token_id1, token_id2, token_id5):
    token_list = []

    for token_id in [token_id1, token_id2,
                     token_id5]:
        token.token_id = token_id
        token_list.append(token)

    return token_list


@pytest.fixture
def mock_list_tokens(monkeypatch, token_id1, token_id2, token_id3, token_id5, token_id4):
    mock_return = Mock()
    mock_return.return_value = [
        Token(cid="username", r=["admin", "lead", "analyst"], cts=datetime(2020, 1, 1),
              ets=datetime(2020, 2, 1), rcid="username", tid=token_id1),
        Token(cid="other_user", r=["admin"], cts=datetime(2020, 1, 1), ets=datetime(2020, 2, 1),
              rcid="username", tid=token_id2),
        Token(cid="username", r=["admin", "lead"], cts=datetime(2019, 1, 1),
              ets=datetime(2019, 2, 1), rcid="username", tid=token_id5),
        Token(cid="other_user", r=[], cts=datetime(2020, 1, 1), ets=datetime(2020, 2, 1),
              rcid="username", tid=token_id3),
        Token(cid="username", r=["analyst"], cts=datetime(2019, 1, 1), ets=datetime(2019, 2, 1),
              rcid="username", tid=token_id4)
    ]

    monkeypatch.setattr(DefaultAuthDB, "list_tokens", mock_return)


@pytest.fixture
def expected_filter_by_user_result(token_id1, token_id5, token_id4):
    return [
        Token(cid="username", r=["admin", "lead", "analyst"], cts=datetime(2020, 1, 1),
              ets=datetime(2020, 2, 1), rcid="username", tid=token_id1),
        Token(cid="username", r=["admin", "lead"], cts=datetime(2019, 1, 1),
              ets=datetime(2019, 2, 1), rcid="username", tid=token_id5),
        Token(cid="username", r=["analyst"], cts=datetime(2019, 1, 1), ets=datetime(2019, 2, 1),
              rcid="username", tid=token_id4)
    ]


@pytest.fixture
def expected_filter_by_role_result(token_id1, token_id4):
    return [
        Token(cid="username", r=["admin", "lead", "analyst"], cts=datetime(2020, 1, 1),
              ets=datetime(2020, 2, 1), rcid="username", tid=token_id1),
        Token(cid="username", r=["analyst"], cts=datetime(2019, 1, 1), ets=datetime(2019, 2, 1),
              rcid="username", tid=token_id4)
    ]


@pytest.fixture
def default_auth_provider():
    return DefaultAuthProvider(username="admin", password="nimda")


class MalformedAuthPackage(AuthPackage):
    def __init__(self):
        super(MalformedAuthPackage, self).__init__()


@pytest.fixture(params=[1, True, [], {"username": "admin", "password": "nimda"}, object()])
def malformed_auth_package(request):
    return request.param


@pytest.fixture(params=[
    {"username": "notadmin", "password": "nimda"},
    {"username": "admin", "password": "notnimda"},
])
def invalid_auth_package(request):
    return DefaultAuthPackage(**request.param)


@pytest.fixture
def default_auth_package():
    return DefaultAuthPackage(username="admin", password="nimda")


@pytest.fixture
def mkdir_raises_permission_error(monkeypatch):
    monkeypatch.setattr(Path, "mkdir", Mock(side_effect=PermissionError))


@pytest.fixture(params=[
    "/token/id/forward/slash",
    "\\token\\path\\back\\slash",
    "4bdad277-16b5-4d9c-a081\\5856d4f348b6",
    "4bdad277-16b5-4d9c-a081/5856d4f348b6"
])
def pathlike_token_id(request):
    return request.param


@pytest.fixture
def pathlike_token(token, pathlike_token_id):
    new_token = deepcopy(token)
    new_token._token_id = pathlike_token_id
    return new_token


@pytest.fixture(params=[
    "admin",
    "user",
    "weirdo",
    "blob",
    1,
    None,
    "flop"
])
def get_client_expected_outcomes(request, admin_role):
    client_id = request.param

    if client_id == "admin":
        return client_id, ClientData(client_id="admin", roles=admin_role)
    else:
        return client_id, None

