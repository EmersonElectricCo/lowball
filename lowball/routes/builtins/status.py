import datetime
import json
from distutils.util import strtobool

from flask import g, current_app, request
from flask.blueprints import Blueprint

from lowball.authentication.wrappers import require_authenticated_user, require_admin
from lowball.exceptions import ListTokensInvalidReturnTypeException, ListTokensInvalidTokenInListException, \
    TokenNotFoundException, BadRequestException, InternalServerErrorException, NotFoundException, \
    MalformedProviderPackageException, InadequateRolesException, MalformedTokenIdException, \
    AuthenticationNotInitializedException
from lowball.models.authentication_models import Token, ClientData, valid_token_id

status = Blueprint("status", __name__, url_prefix="/builtins/status")

_JSON_HEADER = {"Content-Type": "application/json"}

@status.route("/", methods=["GET"], strict_slashes=False)
def get_application_status():
    """Get the status of the Lowball application.

    This view function returns data about the operation of the
    application, namely the name of the application, and whether
    the auth database and auth provider are initialized.

    The auth database is considered initialized if it is not None.

    We determine whether the auth provider is initialized by
    calling :meth:`initialized`. If an exception is thrown, we
    assume the provider is not initialized. If it returns something
    other than a bool, we consider it not initialized.

    :rtype: tuple
    :return: status information, status code, headers
    """
    app_name = current_app.lowball_config.meta.name

    try:
        auth_provider_initialized = current_app.auth_provider.initialized
    except:
        auth_provider_initialized = False

    if not isinstance(auth_provider_initialized, bool):
        auth_provider_initialized = False

    auth_db_initialized = False if current_app.auth_db is None else True

    status_information = {
        "name": app_name,
        "auth_provider_initialized": auth_provider_initialized,
        "auth_db_initialized": auth_db_initialized
    }

    return json.dumps(status_information), 200,  _JSON_HEADER
