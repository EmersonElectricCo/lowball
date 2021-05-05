from flask import g, request


def request_finished_log(sender, response, **extra):
    """Subscriber for request_finished signal

    This subscriber will log pertinent information from the
    response of a view function, using the application logger.
    Exception and normal responses are handled differently.

    :type sender: flask.Flask
    :param sender: the application that is sending the signal
    :type response: flask.Response
    :param response: The response from the view function
    :type extra: dict
    :param extra: container for any extra keywords that get passed in
    :rtype: None
    :return: None
    """
    try:
        request_environment = request.environ
    except AttributeError:
        request_environment = None

    if hasattr(g, "client_data"):
        client_data = {
            "requesting_client": g.client_data.client_id,
            "client_token_id": g.client_data.token_id
        }
    else:
        client_data = {}

    if request_environment:
        log_dict = {
            "user_agent": request_environment.get("HTTP_USER_AGENT", "None"),
            "src_ip": request_environment.get("HTTP_X_FORWARDED_FOR", request_environment.get("REMOTE_ADDR")),
            "http_method": request.method,
            "url": request_environment["werkzeug.request"].full_path,
            "status_code": response.status_code,
            "client_data": client_data
        }

        if hasattr(g, "response_is_exception") and g.response_is_exception:
            message = {"result": response.status, "error_information": g.response_exception_log_data}
            sender.logger.error(message, extra=log_dict)
        else:
            message = {"result": response.status}
            sender.logger.info(message, extra=log_dict)


__all__ = [
    "request_finished_log"
]
