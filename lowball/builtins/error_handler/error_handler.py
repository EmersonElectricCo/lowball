from flask import jsonify, g
from werkzeug.exceptions import HTTPException

from lowball.exceptions import LowballException


def default_error_handler(exception):
    """Default Error Handler for Lowball

    This handler takes the exception information and converts it to json and sets the g repsonse_is_exception
    to true, which will affect log handling down the chain.
    """
    # Build the initial response with the body containing the error message
    response = jsonify(message=str(exception))

    # If its a recognized type of exception handle it accordingly if not 500
    if isinstance(exception, HTTPException):
        response.status_code = exception.code

        if isinstance(exception, LowballException):
            g.response_is_exception = True

            g.response_exception_log_data = exception.additional_log_data
        elif exception.code > 499:
            g.response_is_exception = True

            g.response_exception_log_data = {"error_type": str(type(exception)), "error_msg": str(exception)}

    else:
        g.response_is_exception = True
        response.status_code = 500
        g.response_exception_log_data = {"error_type": str(type(exception)), "error_msg": str(exception)}

    return response
