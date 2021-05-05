import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from lowball.builtins.logging.formatter import DefaultFormatter


class DefaultLoggingHandler(RotatingFileHandler):
    """
    Default log handler for Lowball applications. This handler will be added to
    the builtin flask logger. It basically is a more tightly controlled version of
    the RotatingFileHandler provided by the logging library, with the DefaultFormatter
    set as the formatter.
    """
    LOG_LEVELS = [
        logging.NOTSET,
        logging.DEBUG,
        logging.INFO,
        logging.WARNING,
        logging.ERROR,
        logging.CRITICAL
    ]

    def __init__(self, filename="lowball.log", formatter=None, log_level=logging.DEBUG, max_bytes=2**20,
                 backup_count=5):
        if not isinstance(filename, (str, Path)):
            raise TypeError("filename must be a string or a Path object")

        if formatter is None:
            formatter = {}

        if not isinstance(max_bytes, int):
            raise TypeError("max_bytes must be an int")

        if not isinstance(backup_count, int):
            raise TypeError("backup_count must be an int")

        if log_level not in self.LOG_LEVELS:
            raise ValueError(f"log_level must be one of logging library log level")

        if max_bytes < 0:
            raise ValueError("max_bytes must be zero or greater")

        if backup_count < 0:
            raise ValueError("backup_count must be zero or greater")

        super(DefaultLoggingHandler, self).__init__(filename=filename, maxBytes=max_bytes, backupCount=backup_count)
        self.setLevel(log_level)
        self.setFormatter(DefaultFormatter(**formatter))
