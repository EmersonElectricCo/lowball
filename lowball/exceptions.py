from werkzeug.exceptions import HTTPException


class LowballException(HTTPException):
    """
    Base exception class for Lowball Exceptions
    """
    # Treat all exceptions as 500 unless explicitly overwritten
    code = 500

    # Handle Generic Exceptions
    description = "An Error Occurred. Please Check the Logs For Additional Data"

    # Since we are overwriting the base init class fulfilling the need of setting the response to None
    response = None

    def __init__(self, additional_log_data=None):
        """
        Initialize a Lowball Exception

        :param additional_log_data: additional data that can be placed in the logs but not shown to the user
        """
        # Set the optional Additional Log Data that is not shown to the user
        self.additional_log_data = additional_log_data


class InvalidTokenLifetimeException(LowballException):
    code = 400  # Bad Request
    description = "The Requested Lifetime for the Token Is Not In Range"


class NoAuthHeaderException(LowballException):
    code = 400  # Bad Request
    description = "No token provided with request"


class InvalidAuthHeaderException(LowballException):
    code = 400  # Bad Request
    description = "Authorization header improperly formatted"


class RequestNotJSONException(LowballException):
    code = 400  # Bad Request
    description = "Ill formatted request, the expected body was of type JSON"


class InvalidTokenException(LowballException):
    code = 401  # Unauthorized
    description = "Token Is Invalid"


class MalformedTokenIdException(LowballException):
    code = 400
    description = "Invalid token id format"


class ExpiredTokenException(LowballException):
    code = 401  # Unauthorized
    description = "Token Has Expired"


class InadequateRolesException(LowballException):
    code = 401  # Unauthorized
    description = "Current Token Has Inadequate Roles for Requested Action"


class AuthenticationNotInitializedException(LowballException):
    code = 503  # Service Unavailable
    description = "No Authentication Provider Present"


class InvalidCredentialsException(LowballException):
    code = 401  # Unauthorized
    description = "Invalid credentials supplied"


class MalformedAuthPackageException(LowballException):
    code = 400  # Bad Request
    description = "The Authentication Request Did Not Supply The Required Data"


class MalformedProviderPackageException(LowballException):
    code = 400  # Bad Request
    description = "The Request Did Not Supply The Required Data for the Auth Provider"


class NoAuthenticationDatabaseException(LowballException):
    code = 503
    description = "No authentication database configured for this application"


class InvalidAuthDataException(LowballException):
    description = "Unable to create token. The authentication provider returned an unrecognized response."


class InvalidRequestingUserException(LowballException):
    description = "Attempted to create a token with an invalid requesting user"


class InvalidTokenLifeException(LowballException):
    description = "Attempted to create a token where expiration is greater than configured max token life"


class ListTokensInvalidReturnTypeException(LowballException):
    description = "auth_db.list_tokens did not return a list as expected"


class ListClientsInvalidReturnTypeException(LowballException):
    description = "auth_provider.list_clients did not return a list of client data objects as expected"



class ListTokensInvalidTokenInListException(LowballException):
    description = "auth_db.list_tokens returned a list that included a non-Token object"


class TokenNotFoundException(LowballException):
    code = 404
    description = "Specified token not found"


class BadRequestException(LowballException):
    code = 400

    def __init__(self, description, additional_log_data=None):
        super(BadRequestException, self).__init__(additional_log_data)
        self.description = description


class InternalServerErrorException(LowballException):
    code = 500

    def __init__(self, description, additional_log_data=None):
        super(InternalServerErrorException, self).__init__(additional_log_data)
        self.description = description


class NotFoundException(LowballException):
    code = 404

    def __init__(self, description, additional_log_data=None):
        super(NotFoundException, self).__init__(additional_log_data)
        self.description = description


class NotImplementedException(LowballException):
    code = 501

    def __init__(self, function, additional_log_data=None):
        super(NotImplementedException, self).__init__(additional_log_data)
        self.description = f"{function} not implemented"


LOWBALL_EXCEPTIONS = [
    LowballException,
    InvalidTokenException,
    NoAuthHeaderException,
    InvalidAuthHeaderException,
    RequestNotJSONException,
    InvalidTokenException,
    ExpiredTokenException,
    InadequateRolesException,
    AuthenticationNotInitializedException,
    InvalidCredentialsException,
    MalformedAuthPackageException,
    NoAuthenticationDatabaseException,
    MalformedProviderPackageException,
    MalformedTokenIdException,
    ListClientsInvalidReturnTypeException
]


__all__ = [
    "LowballException",
    "InvalidTokenLifetimeException",
    "NoAuthHeaderException",
    "InvalidAuthHeaderException",
    "RequestNotJSONException",
    "InvalidTokenException",
    "ExpiredTokenException",
    "InadequateRolesException",
    "AuthenticationNotInitializedException",
    "InvalidCredentialsException",
    "MalformedAuthPackageException",
    "NoAuthenticationDatabaseException",
    "LOWBALL_EXCEPTIONS",
    "InvalidAuthDataException",
    "InvalidRequestingUserException",
    "InvalidTokenLifeException",
    "ListTokensInvalidTokenInListException",
    "ListTokensInvalidReturnTypeException",
    "TokenNotFoundException",
    "BadRequestException",
    "InternalServerErrorException",
    "NotFoundException",
    "NotImplementedException",
    "MalformedProviderPackageException",
    "MalformedTokenIdException",
    "ListClientsInvalidReturnTypeException"
]
