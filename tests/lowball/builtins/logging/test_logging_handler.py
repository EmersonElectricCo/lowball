import logging
import pytest

from logging.handlers import RotatingFileHandler

from lowball.builtins.logging.logging_handler import DefaultLoggingHandler


class TestDefaultLoggingHandler:
    @pytest.mark.parametrize("filename, log_level, max_bytes, backup_count, formatter", [
        (1, logging.DEBUG, 2**20, 5, {"date_format": "%Y-%m-%d %H:%M:%S.%fUTC"}),
        ("/path/to/file", logging.DEBUG, "not an int", 5, {"date_format": "%Y-%m-%d %H:%M:%S.%fUTC"}),
        ("/path/to/file", logging.DEBUG, 2**20, "not an int", {"date_format": "%Y-%m-%d %H:%M:%S.%fUTC"}),
        ("/path/to/file", logging.DEBUG, 2**20, 5, "Not a dict")
    ])
    def test_passing_bad_values_at_init_raises_exception(self, filename, log_level, max_bytes, backup_count, formatter,
                                                         mock_open_file):
        with pytest.raises(TypeError):
            DefaultLoggingHandler(filename=filename, log_level=log_level, max_bytes=max_bytes,
                                  backup_count=backup_count, formatter=formatter)

    def test_init_sets_formatter_and_log_level(self, filename, log_level, max_bytes, backup_count, formatter,
                                               monkeypatched_setters, mock_open_file):
        DefaultLoggingHandler(filename=filename, log_level=log_level, max_bytes=max_bytes, backup_count=backup_count,
                              formatter=formatter)
        RotatingFileHandler.setFormatter.assert_called_once()
        RotatingFileHandler.setLevel.assert_called_once_with(log_level)

    def test_passing_bad_log_level_raises_exception(self, filename, bad_log_level, max_bytes, backup_count, formatter,
                                                    mock_open_file):
        with pytest.raises(ValueError):
            DefaultLoggingHandler(filename=filename, log_level=bad_log_level, max_bytes=max_bytes,
                                  backup_count=backup_count, formatter=formatter)

    def test_passing_bad_max_bytes_raises_exception(self, filename, log_level, bad_max_bytes, backup_count, formatter,
                                                    mock_open_file):
        with pytest.raises(ValueError):
            DefaultLoggingHandler(filename=filename, log_level=log_level, max_bytes=bad_max_bytes,
                                  backup_count=backup_count, formatter=formatter)

    def test_passing_bad_backup_count_raises_exception(self, filename, log_level, max_bytes, bad_backup_count,
                                                       formatter,mock_open_file):
        with pytest.raises(ValueError):
            DefaultLoggingHandler(filename=filename, log_level=log_level, max_bytes=max_bytes,
                                  backup_count=bad_backup_count, formatter=formatter)
