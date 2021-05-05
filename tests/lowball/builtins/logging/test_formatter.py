import json
import pytest

from lowball.builtins.logging import DefaultFormatter


class TestDefaultFormatter:
    def test_passing_bad_values_to_init_raises_exception(self, not_string):
        with pytest.raises(TypeError):
            DefaultFormatter(date_format=not_string)

    @pytest.mark.parametrize("created_time, expected_datestr", [
        (1577858400.0, "2020-01-01 06:00:00.000000UTC"),
        (1609488121.000001, '2021-01-01 08:02:01.000001UTC')
    ])
    def test_format_time_method_returns_expected_date_strings(self, default_formatter, created_time, expected_datestr):
        formatted_time = default_formatter._format_time(created_time)
        assert formatted_time == expected_datestr
    
    def test_format_method_properly_formats_verbose_log(self, verbose_log, default_formatter,
                                                        expected_verbose_log_fields, expected_additional_field):
        formatted_log = default_formatter.format(verbose_log)
        assert isinstance(formatted_log, str)
        loaded_log = json.loads(formatted_log)
        assert all(field in loaded_log for field in expected_verbose_log_fields.keys())
        assert all(isinstance(loaded_log[field], data_type) for field, data_type in expected_verbose_log_fields.items())
        assert loaded_log["additional"] == expected_additional_field
        assert all(key not in loaded_log for key in ["requesting_client", "request_id", "client_token_id"])

    def test_format_method_properly_formats_default_log(self, default_log, default_formatter,
                                                        expected_default_log_fields, expected_additional_field):
        formatted_log = default_formatter.format(default_log)
        assert isinstance(formatted_log, str)
        loaded_log = json.loads(formatted_log)
        assert all(field in loaded_log for field in expected_default_log_fields.keys())
        assert all(isinstance(loaded_log[field], data_type) for field, data_type in expected_default_log_fields.items())
        assert loaded_log["additional"] == expected_additional_field
        assert all(key not in loaded_log for key in ["requesting_client", "request_id", "client_token_id"])

    def test_format_method_properly_formats_exception_log(self, exception_log, default_formatter,
                                                          expected_exception_log):
        formatted_log = default_formatter.format(exception_log)
        assert isinstance(formatted_log, str)
        loaded_log = json.loads(formatted_log)
        assert loaded_log == expected_exception_log
        assert all(key not in loaded_log for key in ["requesting_client", "request_id", "client_token_id"])
    
    def test_formatter_adds_flask_data_if_present_for_default_logs(self, default_formatter, default_log, mock_g,
                                                                   token_id, request_id):
        loaded_default_log = json.loads(default_formatter.format(default_log))
        assert loaded_default_log["requesting_client"] == "username"
        assert loaded_default_log["client_token_id"] == token_id
        assert loaded_default_log["request_id"] == request_id

    def test_formatter_adds_flask_data_if_present_for_verbose_logs(self, default_formatter, verbose_log, mock_g,
                                                                   token_id, request_id):
        loaded_verbose_log = json.loads(default_formatter.format(verbose_log))
        assert loaded_verbose_log["requesting_client"] == "username"
        assert loaded_verbose_log["client_token_id"] == token_id
        assert loaded_verbose_log["request_id"] == request_id

    def test_formatter_adds_flask_data_if_present_for_exception_logs(self, default_formatter, exception_log, mock_g,
                                                                     token_id, request_id):
        loaded_exception_log = json.loads(default_formatter.format(exception_log))
        assert loaded_exception_log["requesting_client"] == "username"
        assert loaded_exception_log["client_token_id"] == token_id
        assert loaded_exception_log["request_id"] == request_id
