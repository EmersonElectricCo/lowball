from flask import g

from lowball.builtins.error_handler import default_error_handler
from lowball.builtins.response_class import LowballResponse


class TestDefaultErrorHandler:
    def test_basic_exception_handled_properly(self, basic_exception, client_with_response_class):
        response = default_error_handler(basic_exception)
        assert isinstance(response, LowballResponse)
        assert response.status_code == 500
        assert g.response_is_exception
        assert g.response_exception_log_data == {"error_type": str(type(basic_exception)),
                                        "error_msg": str(basic_exception)}

    def test_lowball_exception_is_handled_properly(self, lowball_exception, client_with_response_class):
        response = default_error_handler(lowball_exception)
        assert isinstance(response, LowballResponse)
        assert response.status_code == lowball_exception.code
        assert g.response_is_exception
        assert g.response_exception_log_data == lowball_exception.additional_log_data

    def test_http_exception_code_less_than_500_handled_properly(self, http_exception_lt_500,
                                                                client_with_response_class):
        response = default_error_handler(http_exception_lt_500)
        assert isinstance(response, LowballResponse)
        assert response.status_code == http_exception_lt_500.code

    def test_http_exception_greater_than_equal_500_handled_properly(self, http_exception_gte_500,
                                                                    client_with_response_class):
        response = default_error_handler(http_exception_gte_500)
        assert isinstance(response, LowballResponse)
        assert response.status_code == http_exception_gte_500.code
        assert g.response_is_exception
        assert g.response_exception_log_data == {"error_type": str(type(http_exception_gte_500)),
                                        "error_msg": str(http_exception_gte_500)}
