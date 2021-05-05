from logging import INFO, ERROR
from unittest.mock import call

from flask import current_app, request, g

from lowball.builtins.signal_subscribers import request_finished_log


class TestRequestFinishedLogSubscriber:
    def test_does_not_do_anything_if_there_is_no_request_environment(self, context_no_request_env, base_response):
        request_finished_log(current_app, base_response)
        current_app.logger._log.assert_not_called()

    def test_response_is_not_exception_handled_properly(self, context_normal_env, base_response):
        log_dict = {
            "user_agent": request.environ.get("HTTP_USER_AGENT", "None"),
            "src_ip": request.environ.get("HTTP_X_FORWARDED_FOR", request.environ.get("REMOTE_ADDR")),
            "http_method": request.method,
            "url": request.environ["werkzeug.request"].full_path,
            "status_code": base_response.status_code,
            "client_data": {
                "requesting_client": g.client_data.client_id,
                "client_token_id": g.client_data.token_id
            }
        }

        log_call = call(
            INFO,                              # Logging level
            {"result": base_response.status},  # The msg of the _log call
            (),                                # container for *args
            extra=log_dict                     # "extra" kwarg
        )
        request_finished_log(current_app, base_response)
        current_app.logger._log.assert_has_calls([log_call])

    def test_response_is_exception_handled_properly(self, context_exception_env, exception_response):
        log_dict = {
            "user_agent": request.environ.get("HTTP_USER_AGENT", "None"),
            "src_ip": request.environ.get("HTTP_X_FORWARDED_FOR", request.environ.get("REMOTE_ADDR")),
            "http_method": request.method,
            "url": request.environ["werkzeug.request"].full_path,
            "status_code": exception_response.status_code,
            "client_data": {
                "requesting_client": g.client_data.client_id,
                "client_token_id": g.client_data.token_id
            }
        }

        msg = {"result": exception_response.status, "error_information": g.response_exception_log_data}

        log_call = call(
            ERROR,          # Logging level
            msg,            # The msg of the _log call
            (),             # container for *args
            extra=log_dict  # "extra" kwarg
        )
        request_finished_log(current_app, exception_response)
        current_app.logger._log.assert_has_calls([log_call])
