from pathlib import Path

import pytest

from lowball.models.config_models import *


@pytest.fixture(params=[
    ["string", "list", "with", "number", 1],
    ["string", "list", "with", "bool", True],
    ["string", "list", "with", "object", object()],
])
def invalid_tags(request):
    return request.param


@pytest.fixture(params=[
    "base-route-doesnt-start-with-slash"
])
def invalid_base_route(request):
    return request.param


@pytest.fixture
def auth_db_config():
    return {
        "db_host": "database.test.com",
        "db_port": 9999,
        "db_user": "root",
        "db_password": "BadPass01"
    }


@pytest.fixture
def auth_provider_config():
    return {
        "field1": 1,
        "field2": "string"
    }


@pytest.fixture
def logging_config():
    return {
        "logging_path": "/var/log/app/app.log"
    }


@pytest.fixture
def application_config():
    return {
        "field1": 1,
        "field2": "string"
    }


@pytest.fixture
def config_dict():
    return {
        "meta": {
            "name": "APP_NAME",
            "base_route": "/base/route",
            "description": "description",
            "tags": [
                "tag",
                "list"
            ]
        },
        "authentication": {
            "default_token_life": 1800,
            "max_token_life": 1800,
            "token_secret": "supersecrettokensecret"
        },
        "application": {
            "field1": 1,
            "field2": "string"
        },
        "auth_provider": {
            "field1": 1,
            "field2": "string"
        },
        "auth_db": {
            "db_host": "database.test.com",
            "db_port": 9999,
            "db_user": "root",
            "db_password": "BadPass01"
        },
        "logging": {
            "logging_path": "/var/log/app/app.log"
        }
    }


@pytest.fixture(params=[1, "string", [1, 2, 3], ("tuple",), {1, 2, 3}])
def not_dict(request):
    return request.param


@pytest.fixture(params=[
    {"meta": {"name": "APP_NAME", "base_route": "/base/route", "description": "description", "tags": ["tag", "list"]},
     "authentication": {"default_token_life": 1800, "max_token_life": 1800, "token_secret": "supersecrettokensecret", "ignore_auth": False},
     "application": {"field1": 1, "field2": "string"}, "auth_provider": {"field1": 1, "field2": "string"},
     "auth_db": {"db_host": "database.test.com", "db_port": 9999, "db_user": "root", "db_password": "BadPass01"},
     "logging": {"logging_path": "/var/log/app/app.log"}},
    {"meta": {"name": "APP_NAME", "base_route": "/base/route", "description": "description", "tags": ["tag", "list"]},
     "authentication": {"default_token_life": 1800, "max_token_life": 1800, "token_secret": "supersecrettokensecret", "ignore_auth": False},
     "application": {}, "auth_provider": {}, "auth_db": {}, "logging": {}}
])
def json_config_object(request):
    return request.param


@pytest.fixture(params=[
    "/path/to/config.json",
    Path("/path/to/config.json")
])
def json_config_path(request):
    return request.param


@pytest.fixture
def json_file_read_data():
    return '{\n  "meta": {\n    "name": "APP_NAME",\n    "base_route": "/base/route",\n    "description": "description",\n    "tags": [\n      "tag",\n      "list"\n    ]\n  },\n  "application": {\n    "field1": 1,\n    "field2": "string"\n  },\n  "auth_provider": {\n    "field1": 1,\n    "field2": "string"\n  },\n  "auth_db": {\n    "db_host": "database.test.com",\n    "db_port": 9999,\n    "db_user": "root",\n    "db_password": "BadPass01"\n  },\n  "logging": {\n    "logging_path": "/var/log/app/app.log"\n  },\n  "authentication": {\n    "default_token_life": 1800,\n    "max_token_life": 1800,\n    "token_secret": "supersecrettokensecret",\n    "ignore_auth": false\n  }\n}'


@pytest.fixture(params=[
    "/path/to/config.yaml",
    Path("/path/to/config.yaml")
])
def yaml_config_path(request):
    return request.param


@pytest.fixture
def yaml_file_read_data():
    return 'meta:\n  name: APP_NAME\n  base_route: /base/route\n  description: description\n  tags:\n  - tag\n  - list\napplication:\n  field1: 1\n  field2: string\nauth_provider:\n  field1: 1\n  field2: string\nauth_db:\n  db_host: database.test.com\n  db_port: 9999\n  db_user: root\n  db_password: BadPass01\nlogging:\n  logging_path: /var/log/app/app.log\nauthentication:\n  default_token_life: 1800\n  max_token_life: 1800\n  token_secret: supersecrettokensecret\n  ignore_auth: false\n'


@pytest.fixture(params=["1", "1234", "1234567890"])
def int_as_string(request):
    return request.param


@pytest.fixture(params=[{}, [], object(), True, 1.1])
def not_like_int(request):
    return request.param


@pytest.fixture(params=[{}, [], object(), 0, 1.1, "string"])
def not_bool(request):
    return request.param


@pytest.fixture
def auth_config_dict(default_token_life, max_token_life, token_secret):
    return {
        "default_token_life": int(default_token_life),
        "max_token_life": int(max_token_life),
        "token_secret": token_secret,
    }
