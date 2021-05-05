import pytest
from werkzeug.exceptions import HTTPException

from lowball.exceptions import LOWBALL_EXCEPTIONS


@pytest.fixture(params=[
    Exception("test exception"),
    TypeError("test exception"),
    ValueError("test exception"),
    AttributeError("test exception")
])
def basic_exception(request):
    return request.param


@pytest.fixture(params=[exception("test exception") for exception in LOWBALL_EXCEPTIONS])
def lowball_exception(request):
    return request.param


http_exception1 = HTTPException("test exception")
http_exception1.code = 400
http_exception2 = HTTPException("test exception")
http_exception2.code = 401
http_exception3 = HTTPException("test exception")
http_exception3.code = 404


@pytest.fixture(params=[
    http_exception1,
    http_exception2,
    http_exception3
])
def http_exception_lt_500(request):
    return request.param


http_exception4 = HTTPException("test exception")
http_exception4.code = 500
http_exception5 = HTTPException("test exception")
http_exception5.code = 501
http_exception6 = HTTPException("test exception")
http_exception6.code = 503


@pytest.fixture(params=[
    http_exception4,
    http_exception5,
    http_exception6
])
def http_exception_gte_500(request):
    return request.param
