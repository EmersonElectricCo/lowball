import json
import logging

from copy import deepcopy
from datetime import datetime
from flask import g, request


class DefaultFormatter(logging.Formatter):
    """
    Default formatter for Lowball applications. This formatter is designed to log in a
    JSON format, and will log different data depending on the level of log that is being
    logged. Debug logs have more data than Info logs, for example. It also handles some
    renaming of the fields, and stores data that the user adds to the log in a field
    called `additional`.

    :type date_format: str
    :param date_format: the strftime format string used to format datetime strings for
                        log timestamps
    """
    DEFAULT_LOG_FIELDS = [
        "msg",
        "name",
        "args",
        "timestamp",
        "level",
        "additional"
    ]

    VERBOSE_LOG_FIELDS = DEFAULT_LOG_FIELDS + [
        "filename",
        "func_name",
        "line_number",
        "module",
        "pathname",
        "process",
        "process_name",
        "thread_name",
        "thread",
    ]

    EXCEPTION_ERROR_FIELDS = VERBOSE_LOG_FIELDS + [
        "exc_info",
        "stack_info"
    ]

    LOG_RECORD_FIELDS = [
        'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename', 'funcName', 'levelname', 'levelno', 'lineno',
        'module', 'msecs', 'message', 'msg', 'name', 'pathname', 'process', 'processName', 'relativeCreated',
        'stack_info', 'thread', 'threadName'
    ]

    RECORD_ATTRIBUTE_TRANSFORM = [
        ("funcName", "func_name"),
        ("lineno", "line_number"),
        ("levelname", "level"),
        ("processName", "process_name"),
        ("threadName", "thread_name")
    ]

    DEFAULT_LOG_LEVELS = ["NOTSET", "INFO", "WARNING"]

    EXCEPTION_ERROR_LOG_LEVELS = ["ERROR", "CRITICAL"]

    def __init__(self, date_format="%Y-%m-%d %H:%M:%S.%fUTC", **kwargs):
        self.date_format = date_format
        super(DefaultFormatter, self).__init__(datefmt=self.date_format)

    @property
    def date_format(self):
        return self._date_format

    @date_format.setter
    def date_format(self, value):
        if not isinstance(value, str):
            raise TypeError("dated_format must be a string")
        self._date_format = value

    def _format_time(self, timestamp):
        """Format a timestamp into the proper date string

        :type timestamp: float
        :param timestamp: UTC epoch timestamp
        :rtype: str
        :return: date time string
        """
        dt = datetime.utcfromtimestamp(timestamp)
        return dt.strftime(self.date_format)

    def _fix_attribute_names(self, record: logging.LogRecord):
        """Transform record field names from camel case to underscored."""
        for attribute, transform in self.RECORD_ATTRIBUTE_TRANSFORM:
            value = record.__getattribute__(attribute)
            record.__setattr__(transform, value)

        return record

    def _get_additional(self, record: logging.LogRecord):
        """Map all record fields that are not default record fields into their own dictionary."""
        additional = {k: v for k, v in record.__dict__.items() if k not in self.LOG_RECORD_FIELDS}
        return additional

    def format(self, record: logging.LogRecord):
        """Format a log record.

        This method takes the log record and transforms it into a properly formatted
        JSON string.

        :type record: logging.LogRecord
        :param record: Log record generated by logger
        :rtype: str
        :return: Log in JSON format
        """
        copied = deepcopy(record)
        copied.additional = self._get_additional(copied)
        copied.timestamp = self._format_time(copied.created)

        copied = self._fix_attribute_names(copied)

        if copied.level in self.DEFAULT_LOG_LEVELS:
            keep_fields = self.DEFAULT_LOG_FIELDS
        elif copied.level in self.EXCEPTION_ERROR_LOG_LEVELS:
            keep_fields = self.EXCEPTION_ERROR_FIELDS
            if copied.exc_info:
                copied.exc_info = self.formatException(copied.exc_info)
            if copied.stack_info:
                copied.stack_info = self.formatStack(copied.stack_info)
        else:
            keep_fields = self.VERBOSE_LOG_FIELDS

        log = {k: v for k, v in copied.__dict__.items() if k in keep_fields}

        try:
            user_data = g.client_data
            log["requesting_client"] = user_data.client_id
            log["client_token_id"] = user_data.token_id
        except:
            pass

        try:
            log["request_id"] = request.rid
        except:
            pass

        return json.dumps(log)


__all__ = [
    "DefaultFormatter"
]
