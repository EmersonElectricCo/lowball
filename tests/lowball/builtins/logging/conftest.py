import builtins
import flask
import logging
import pytest

from logging.handlers import RotatingFileHandler
from pathlib import Path
from unittest.mock import Mock, mock_open

from lowball.builtins.logging import DefaultFormatter


@pytest.fixture
def log_record():
    return logging.makeLogRecord({
        "args": (),
        "asctime": "2020-12-21 00:00:00,000",
        "created": 1608530400.0,
        "filename": "test.py",
        "funcName": "function1",
        "levelname": "INFO",
        "levelno": 20,
        "lineno": 23,
        "module": "test",
        "msecs": 0,
        "msg": "Test Message",
        "name": "logger",
        "pathname": "/home/username/test.py",
        "process": 5985,
        "processName": "MainProcess",
        "stack_info": None,
        "thread": 139625468991296,
        "threadName": "MainThread",
        "another": "pair"
    })


@pytest.fixture
def date_format():
    return "%Y-%m-%d %H:%M:%S.%fUTC"


@pytest.fixture
def default_formatter(date_format):
    return DefaultFormatter(date_format=date_format)


@pytest.fixture(params=[
    ("DEBUG", 10),
])
def verbose_log(log_record, request):
    log_record.levelname = request.param[0]
    log_record.levelno = request.param[1]
    return log_record


@pytest.fixture(params=[
    ("INFO", 20),
    ("WARNING", 30),
])
def default_log(log_record, request):
    log_record.levelname = request.param[0]
    log_record.levelno = request.param[1]
    return log_record


@pytest.fixture
def exc_info():
    # Turns out it is really difficult to mock tracebacks
    # Code pulled from https://stackoverflow.com/a/19258720
    class FakeCode(object):
        def __init__(self, co_filename, co_name):
            self.co_filename = co_filename
            self.co_name = co_name

    class FakeFrame(object):
        def __init__(self, f_code, f_globals, f_back=None):
            self.f_code = f_code
            self.f_globals = f_globals
            self.f_back = f_back

    class FakeTraceback(object):
        def __init__(self, frames, line_nums):
            if len(frames) != len(line_nums):
                raise ValueError("Ya messed up!")
            self._frames = frames
            self._line_nums = line_nums
            self.tb_frame = frames[0]
            self.tb_lineno = line_nums[0]

        @property
        def tb_next(self):
            if len(self._frames) > 1:
                return FakeTraceback(self._frames[1:], self._line_nums[1:])

    class FakeException(Exception):
        def __init__(self, *args, **kwargs):
            self._tb = None
            super().__init__(*args, **kwargs)

        @property
        def __traceback__(self):
            return self._tb

        @__traceback__.setter
        def __traceback__(self, value):
            self._tb = value

        def with_traceback(self, value):
            self._tb = value
            return self

    # The fake code coincides with the filename and function that are in the
    # mocked log record defined above
    fake_code = FakeCode("test.py", "function1")

    # No need to fake globals here
    fake_frame = FakeFrame(fake_code, f_globals={})

    # Since the mocked log record above has the logging of the exception occurring
    # on line 23 of the fake `test.py` file, we will mock the line number that the
    # exception actually occurred on to be line 20
    exception_line_no = 20

    fake_tb = FakeTraceback(frames=[fake_frame], line_nums=[exception_line_no])
    return FakeException, FakeException("you messed up").with_traceback(fake_tb), fake_tb


@pytest.fixture(params=[
    ("ERROR", 10),
    ("CRITICAL", 50)
])
def exception_log(exc_info, log_record):
    log_record.levelname = "ERROR"
    log_record.levelno = 40
    log_record.exc_info = exc_info

    # Setting stack info to None. I believe that in the case that we are mocking,
    # it makes sense for it to be None
    log_record.stack_info = None
    return log_record


@pytest.fixture
def expected_additional_field():
    return {"another": "pair"}


@pytest.fixture
def expected_default_log_fields():
    return {
        "msg": str,
        "name": str,
        "args": list,
        "timestamp": str,
        "level": str,
        "additional": dict
    }


@pytest.fixture
def expected_verbose_log_fields(expected_default_log_fields):
    expected_default_log_fields.update({
        "filename": str,
        "func_name": str,
        "line_number": int,
        "module": str,
        "pathname": str,
        "process": int,
        "process_name": str,
        "thread": int,
        "thread_name": str
    })
    return expected_default_log_fields


@pytest.fixture
def expected_exception_log():
    return {
        "msg": "Test Message",
        "name": "logger",
        "args": [],
        "timestamp": "2020-12-21 06:00:00.000000UTC",
        "level": "ERROR",
        "additional": {"another": "pair"},
        "filename": "test.py",
        "func_name": "function1",
        "line_number": 23,
        "module": "test",
        "pathname": "/home/username/test.py",
        "process": 5985,
        "process_name": "MainProcess",
        "stack_info": None,
        "thread": 139625468991296,
        "thread_name": "MainThread",
        "exc_info": 'Traceback (most recent call last):\n  File "test.py", line 20, in function1\ntests.lowball.builtins.logging.conftest.exc_info.<locals>.FakeException: you messed up',
    }


@pytest.fixture(params=["/path/to/file.txt", Path("/path/to/file.txt")])
def filename(request):
    return request.param


@pytest.fixture(params=[
    logging.DEBUG,
    logging.INFO,
    logging.WARNING,
    logging.ERROR,
    logging.CRITICAL
])
def log_level(request):
    return request.param


@pytest.fixture(params=[2**20, 0])
def max_bytes(request):
    return request.param


@pytest.fixture(params=[0, 5, 20000])
def backup_count(request):
    return request.param


@pytest.fixture(params=[
    None,
    {},
    {"date_format": "%Y-%m-%d %H:%M:%S.%fUTC"}
])
def formatter(request):
    return request.param


@pytest.fixture
def monkeypatched_setters(monkeypatch):
    monkeypatch.setattr(RotatingFileHandler, "setFormatter", Mock(return_value=None))
    monkeypatch.setattr(RotatingFileHandler, "setLevel", Mock(return_value=None))


@pytest.fixture(params=[-1, 100, "not an int", {}, [], True, 1.1])
def bad_log_level(request):
    return request.param


@pytest.fixture
def bad_max_bytes():
    return -1


@pytest.fixture
def bad_backup_count():
    return -1


@pytest.fixture
def mock_open_file(monkeypatch):
    mock_file = mock_open()
    monkeypatch.setattr(builtins, "open", mock_file)
    return mock_file


@pytest.fixture
def request_id():
    return "01c19a54-1253-4b22-8a1a-004a511594d5"


@pytest.fixture
def mock_g(monkeypatch, expected_token, client, request_id):
    with client.test_client():
        with client.test_request_context() as client:
            flask.request.rid = request_id
            flask.g.client_data = expected_token
            yield client
