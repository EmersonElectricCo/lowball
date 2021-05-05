import json
from unittest.mock import Mock

import pytest
from flask import Response

from lowball.builtins.response_class import LowballResponse


@pytest.fixture
def dict_return_value():
    return {"string": "value", "int": 1, "float": 1.2, "list": [1, 2, 3], "bool": False}


@pytest.fixture
def expected_dict_return(dict_return_value):
    return json.dumps(dict_return_value, separators=(',', ':'), sort_keys=True).encode() + b"\n"


@pytest.fixture(params=[
    [1, 2, 3],
    (1, 2, 3),
    {1, 2, 3},
    frozenset({1, 2, 3}),
    range(1, 4)
])
def sequence_return_value(request):
    return request.param


@pytest.fixture(params=[1, 2, 3])
def int_return_value(request):
    return request.param


@pytest.fixture(params=[1.1, 2.2, 3.3])
def float_return_value(request):
    return request.param


@pytest.fixture(params=[complex(1, 1), complex(2, 2), complex(3, 3)])
def complex_return_value(request):
    return request.param


@pytest.fixture(params=[memoryview(b"hello"), memoryview(b"world"), memoryview(b"something")])
def memoryview_return_value(request):
    return request.param


@pytest.fixture
def mocked_response_force_type(monkeypatch):
    monkeypatch.setattr(Response, "force_type", Mock(return_value=LowballResponse(response="fake_data")))


@pytest.fixture
def response_return_value():
    return Response("fake data")
