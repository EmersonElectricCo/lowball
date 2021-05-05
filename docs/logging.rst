.. _logging:

Logging
#######

Lowball allows you to use any python supported logging
`handler <https://docs.python.org/3/library/logging.html#logging.Handler>`_ and
`formatter <https://docs.python.org/3/library/logging.html#formatter-objects>`_. The only lowball specific consideration
is if your chosen logger requires any config.

Like the Authentication Providers and Databases, any config variables needed by your logger will be mapped by the config
directly to the corresponding `__init__` arguments. A simple example of this is below.

Given the following handler

.. code-block:: python

    from logging.handlers import  SocketHandler

    class CustomLogHandler(SocketHandler):
        def __init__(self, host, port, **kwargs):
            super(CustomLogHandler, self).__init__(host, port)
            ...


The logging section of our config might look like:

.. code-block:: yaml

    logging:
      host: 127.0.0.1
      port: 4500


Default Logging Handler
***********************

The default logging handler in lowball is a `RotatingFileHandler` that outputs the logs in JSON format.

The all optional available configuration values are:

`filename`
  File that the logger will write to. By default, this is `./lowball.log`.

`formatter`
  A dictionary that is used to instantiate the formatter for the log handler.

`log_level`
  The minimum level of log that is to be recorded by the logger. These follow the python standards.

`max_bytes`
  A value that defines the maximum number of bytes that can be written to the log file before it is rolled over or
  overwritten. This value defaults to 2^20 bytes, or 1mb, and must be a number greater than 0.

`backup_count`
  Defines the number of rolled-over log files that are kept by the logging handler. This value defaults to 5 and must be
  a number greater than 0.

**Example Logging Config**

.. code-block:: yaml

    logging:
      filename: /var/log/app/app.log
      formatter:
         date_format: "%Y-%m-%d %H:%M:%S.%fUTC"
      log_level: DEBUG
      max_bytes: 1048576
      backup_count: 5

**Example Non-Verbose Log**

.. code-block:: json

    {
      "name": "myApp",
      "msg": {
        "result": "401 UNAUTHORIZED",
        "error_information": null
      },
      "args": [],
      "additional": {
         "user_agent": "curl/7.68.0",
         "src_ip": "127.0.0.1",
         "http_method": "POST",
         "url": "/launch",
         "status_code": 401,
         "user_data": {
            "requesting_user": "jeff",
            "client_token_id": "0347303c-ffc9-46ea-bded-22e3258dd3b2",
         }
      },
      "timestamp": "2021-02-09 15:36:05.062443UTC",
      "level": "ERROR",
      "requesting_user": "jeff",
      "client_token_id": "0347303c-ffc9-46ea-bded-22e3258dd3b2",
      "request_id": "70047f54-d296-4a57-b7cd-b087fa72f269"
    }


**Example Verbose Log**

.. code-block:: json

    {
      "name": "myApp",
      "msg": {
        "result": "401 UNAUTHORIZED",
        "error_information": null
      },
      "args": [],
      "pathname": "/path/to/calling/file/request_finished_log.py",
      "filename": "request_finished_log.py",
      "module": "request_finished_log",
      "exc_info": null,
      "stack_info": null,
      "thread": 140111293720320,
      "process": 54683,
      "additional": {
         "user_agent": "curl/7.68.0",
         "src_ip": "127.0.0.1",
         "http_method": "POST",
         "url": "/launch",
         "status_code": 401,
         "user_data": {
            "requesting_client": "jeff",
            "client_token_id": "0347303c-ffc9-46ea-bded-22e3258dd3b2",
         }
      },
      "timestamp": "2021-02-09 15:36:05.062443UTC",
      "func_name": "request_finished_log",
      "line_number": 45,
      "level": "ERROR",
      "process_name": "MainProcess",
      "thread_name": "Thread-3",
      "requesting_client": "jeff",
      "client_token_id": "0347303c-ffc9-46ea-bded-22e3258dd3b2",
      "request_id": "70047f54-d296-4a57-b7cd-b087fa72f269"
    }