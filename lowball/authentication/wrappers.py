import datetime
from functools import wraps

from flask import request, current_app, g

from lowball.exceptions import NoAuthHeaderException, InvalidAuthHeaderException, ExpiredTokenException, \
    InvalidTokenException, InadequateRolesException, NoAuthenticationDatabaseException


def validate_auth_header(headers):
    """Validate and decode auth token in request headers.

    This helper function is used in each of the below wrappers, and is responsible to
    validate the format of the `Authorization` header where the Lowball token is
    supposed to reside.

    Requirements for successful validation:
    1. The current app must have a working auth database
    2. The `Authorization` header __must__ be present in the headers
    3. That header value __must__ be of the format `Bearer <token>`. The header value
       is split on the space character, and if the header value is properly formatted,
       this should result in a data structure that looks like ["Bearer", "<token>"]. If
       after splitting the header value on the space, the length of the resulting
       structure is not __exactly__ two, then the header is considered improperly formatted.
    4. The token must be able to be decoded by the `Authentication.decode_token` method
    5. The token cannot be expired.
    6. The token must match a token that is in the application authentication database __exactly__

    :param headers: Headers from request made to Lowball application
    :type headers: werkzeug.Headers
    :return: decoded token data
    :rtype: Token
    """
    if current_app.auth_db is None:
        raise NoAuthenticationDatabaseException

    if "Authorization" not in headers:
        raise NoAuthHeaderException

    auth_header = headers["Authorization"].split(" ")

    if len(auth_header) < 2 or auth_header[0] != "Bearer":
        raise InvalidAuthHeaderException

    token = auth_header[1]

    decoded = current_app.authenticator.decode_token(token)

    g.client_data = decoded

    if datetime.datetime.utcnow() > decoded.expiration:
        raise ExpiredTokenException

    database_token = current_app.auth_db.lookup_token(decoded.token_id)

    if database_token != decoded:
        raise InvalidTokenException

    return decoded


def require_authenticated_user(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        """Wrapper to ensure an authenticated user is accessing the route.

        This wrapper does not care about the roles that are associated with the user
        who is accessing the route. All that matters is that the token that is provided
        is in fact a valid token.
        """
        validate_auth_header(request.headers)

        return func(*args, **kwargs)

    return wrapped


def require_admin(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        """Wrapper to ensure a user with the admin role is accessing the route."""
        decoded = validate_auth_header(request.headers)

        if "admin" not in decoded.roles:
            raise InadequateRolesException

        return func(*args, **kwargs)

    return wrapped


def require_any_of_these_roles(roles=None):
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            """Wrapper to ensure that the user accessing the route has at least one of any number of roles."""
            r = [] if roles is None else roles

            decoded = validate_auth_header(request.headers)

            if not any(role in decoded.roles for role in r):
                raise InadequateRolesException

            return func(*args, **kwargs)

        return wrapped

    return decorator


def require_all_of_these_roles(roles=None):
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            """Wrapper to ensure that the user accessing the route has all of any number of roles."""
            r = [] if roles is None else roles

            decoded = validate_auth_header(request.headers)

            if not all(role in decoded.roles for role in r):
                raise InadequateRolesException

            return func(*args, **kwargs)

        return wrapped

    return decorator


__all__ = [
    "require_authenticated_user",
    "require_admin",
    "require_any_of_these_roles",
    "require_all_of_these_roles",
    "validate_auth_header"
]
