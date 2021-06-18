import datetime
import json
from distutils.util import strtobool

from flask import g, current_app, request
from flask.blueprints import Blueprint

from lowball.authentication.wrappers import require_authenticated_user, require_admin
from lowball.exceptions import ListTokensInvalidReturnTypeException, ListTokensInvalidTokenInListException, \
    TokenNotFoundException, BadRequestException, InternalServerErrorException, NotFoundException, \
    MalformedProviderPackageException, InadequateRolesException, MalformedTokenIdException, \
    AuthenticationNotInitializedException, NoAuthenticationDatabaseException, NotImplementedException, \
    MalformedAuthPackageException, ListClientsInvalidReturnTypeException

from lowball.models.authentication_models import Token, ClientData, valid_token_id

auth = Blueprint("auth", __name__, url_prefix="/builtins/auth")

_JSON_HEADER = {"Content-Type": "application/json"}


@auth.route("/", methods=["POST"], strict_slashes=False)
def login():
    """Login a client to the Lowball application.

        The POST body of this request is going to be whatever is necessary to create
        the type of auth package that is configured to be used by the auth provider of
        this application. That data will be mapped into the __init__ of the auth provider
        package class. That auth package will be used to authenticate against the
        configured auth provider. The return data from that operation will be passed
        into the authenticator, which will create a token that is returned to the client.

        :rtype: tuple
        :return: token and token data, status code
        """
    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException

    if current_app.auth_db is None:
        raise NoAuthenticationDatabaseException

    post_data = request.get_json()

    auth_package_class = current_app.auth_provider.auth_package_class
    if not auth_package_class:
        raise NotImplementedException("auth_package_class",
                                      "The auth provider has not defined an authentication package")
    try:
        auth_package = auth_package_class(**post_data)
    except Exception as err:
        raise MalformedAuthPackageException(str(err))

    client_data = current_app.auth_provider.authenticate(auth_package)
    if not isinstance(client_data, ClientData):
        raise NotImplementedException("authenticate", "the auth provider is not returning a ClientData object")
    token, token_data = current_app.authenticator.create_token(client_id=client_data.client_id, roles=client_data.roles)
    current_app.logger.info(f"Successful login for {token_data.client_id}",
                            extra={"client_id": token_data.client_id, "token_id": token_data.token_id})

    current_app.auth_db.add_token(token_data)

    return json.dumps({"token": token, "token_data": token_data.to_dict()}), 200, _JSON_HEADER


@auth.route("/", methods=["DELETE"], strict_slashes=False)
@require_authenticated_user
def logout():
    """Logout a client from the Lowball application.

        This route simply revokes the token that is used to make the request.

        :rtype: tuple
        :return: empty response, status code
        """
    token_data = g.client_data
    current_app.auth_db.revoke_token(token_data.token_id)
    current_app.logger.info(f"Successfully logged out {token_data.client_id}",
                            extra={"client_id": token_data.client_id, "token_id": token_data.token_id})
    return "", 204


@auth.route("/", methods=["GET"], strict_slashes=False)
@require_authenticated_user
def whoami():
    """Get data for user token."""
    token_data = g.client_data.to_dict()
    return json.dumps(token_data), 200, _JSON_HEADER


@auth.route("/tokens", methods=["GET"], strict_slashes=False)
@require_authenticated_user
def get_current_client_tokens():
    """Get a list of all tokens in the application auth database.

        The tokens that are returned can be filtered by role, username and whether
        the token is expired. These filters are passed in the query params of the
        request. If there are multiple values passed in for username or roles, then
        any token that has any of those usernames or roles will be returned.

        The include_expired query param can be used to filter out tokens that are
        expired, but this defaults to True, so the normal operation of this view
        function is to return all tokens, both expired and not.

        :rtype: tuple
        :return: list of tokens, status code
        """

    client_data = g.client_data
    now = datetime.datetime.utcnow()
    roles = request.args.getlist("roles")
    # non admin clients cannot lookup tokens for other users

    exclude_expired = request.args.get("exclude_expired", "").lower() == "yes"

    tokens = current_app.auth_db.list_tokens_by_client_id(client_data.client_id)

    if not isinstance(tokens, list):
        raise ListTokensInvalidReturnTypeException

    if not any(isinstance(token, Token) for token in tokens):
        raise ListTokensInvalidTokenInListException

    if roles:
        tokens = [token for token in tokens if any(role in token.roles for role in roles)]

    if exclude_expired:
        tokens = [token for token in tokens if token.expiration > now]

    return json.dumps([token.to_dict() for token in tokens]), 200, _JSON_HEADER


@auth.route("/tokens", methods=["POST"], strict_slashes=False)
@require_authenticated_user
def create_token():
    """Create a new token for the specified user or self user

        Things to note:
            - A client_id is required to make a token
            - If no roles are supplied in the POST body, then the roles for the
              user will be assigned to an empty array (no roles)
            - If no token life is present in the POST body, then the configured default
              token life will be used.
            - Token life must be a positive integer greater than 9.

        :rtype: tuple
        :return: token data, status code
        """
    post_data = request.get_json()
    if post_data is None:
        post_data = {}
    default_token_life = current_app.lowball_config.authentication.default_token_life
    max_token_life = current_app.lowball_config.authentication.max_token_life
    requesting_client_data = g.client_data
    requesting_client_roles = requesting_client_data.roles
    admin_user = "admin" in requesting_client_roles
    requesting_user = requesting_client_data.client_id
    client_id = post_data.get("client_id")

    if client_id and not admin_user and requesting_client_data.client_id != client_id:
        raise InadequateRolesException("Unable to create tokens for another client")

    if not client_id:
        client_id = requesting_user

    requested_roles = post_data.get("roles", [])
    try:
        token_life = default_token_life if post_data.get("token_life") is None else int(post_data["token_life"])
    except:
        raise BadRequestException(
            f"token_life must be a positive integer greater than 10 and less than {max_token_life}")

    if not isinstance(token_life, int) or token_life < 10 or token_life > max_token_life:
        raise BadRequestException(
            f"token_life must be a positive integer greater than 10 and less than {max_token_life}")

    if not admin_user:
        if current_app.auth_provider is None:
            raise AuthenticationNotInitializedException

        try:
            target_client = current_app.auth_provider.get_client(client_id)
        except NotImplementedException as err:
            err.code = 409
            err.description = "get_client is not implemented in this auth provider. " \
                              "Non admin clients are unable to create tokens"
            raise err

        if not target_client:
            raise NotFoundException("Client ID for requesting token not found in auth provider")
        target_client_roles = target_client.roles
        if any(role not in target_client_roles for role in requested_roles):
            raise InadequateRolesException("Unable to create token with requested roles")
    roles = requested_roles

    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=token_life)

    token, token_data = current_app.authenticator.create_token(client_id, roles, requesting_user, expiration_time)
    current_app.auth_db.add_token(token_data)

    return json.dumps({"token": token, "token_data": token_data.to_dict()}), 201, _JSON_HEADER


@auth.route("/tokens", methods=["DELETE"], strict_slashes=False)
@require_authenticated_user
def delete_current_client_tokens():
    """Revoke all the tokens for the specified client in the auth db."""

    client_information = g.client_data

    client_id = client_information.client_id

    tokens = current_app.auth_db.list_tokens_by_client_id(client_id)

    if not isinstance(tokens, list):
        raise ListTokensInvalidReturnTypeException

    if any(not isinstance(token, Token) for token in tokens):
        raise ListTokensInvalidTokenInListException

    for token in tokens:
        current_app.auth_db.revoke_token(token.token_id)

    return "", 204


@auth.route("/tokens/all", methods=["GET"], strict_slashes=False)
@require_admin
def get_all_tokens():
    """Get a list of all tokens in the application auth database.

        The tokens that are returned can be filtered by role, username and whether
        the token is expired. These filters are passed in the query params of the
        request. If there are multiple values passed in for username or roles, then
        any token that has any of those usernames or roles will be returned.

        The include_expired query param can be used to filter out tokens that are
        expired, but this defaults to True, so the normal operation of this view
        function is to return all tokens, both expired and not.

        :rtype: tuple
        :return: list of tokens, status code
        """

    now = datetime.datetime.utcnow()
    roles = request.args.getlist("roles")
    clients = request.args.getlist("client_ids")

    exclude_expired = request.args.get("exclude_expired", "").lower() == "yes"
    tokens = current_app.auth_db.list_tokens()
    if not isinstance(tokens, list):
        raise ListTokensInvalidReturnTypeException

    if not any(isinstance(token, Token) for token in tokens):
        raise ListTokensInvalidTokenInListException

    if roles:
        tokens = [token for token in tokens if any(role in token.roles for role in roles)]
    if clients:
        tokens = [token for token in tokens if any(client == token.client_id for client in clients)]

    if exclude_expired:
        tokens = [token for token in tokens if token.expiration > now]

    return json.dumps([token.to_dict() for token in tokens]), 200, _JSON_HEADER


@auth.route("/tokens/all", methods=["DELETE"], strict_slashes=False)
@require_admin
def delete_all_tokens():
    """Revoke all the tokens that are in the application auth database."""

    roles = request.args.getlist("roles")
    clients = request.args.getlist("client_ids")

    if not roles and not clients:
        current_app.auth_db.revoke_all()
        return "", 204

    tokens = current_app.auth_db.list_tokens()
    if not isinstance(tokens, list):
        raise ListTokensInvalidReturnTypeException

    if not any(isinstance(token, Token) for token in tokens):
        raise ListTokensInvalidTokenInListException

    if roles:
        tokens = [token for token in tokens if any(role in token.roles for role in roles)]
    if clients:
        tokens = [token for token in tokens if any(client == token.client_id for client in clients)]

    for token in tokens:
        current_app.auth_db.revoke_token(token.token_id)

    return "", 204

@auth.route("/tokens/cleanup", methods=["POST"], strict_slashes=False)
@require_admin
def cleanup_tokens():
    """Delete all expired tokens in the application auth database."""
    current_app.auth_db.cleanup_tokens()
    return "", 204


@auth.route("/tokens/<token_id>", methods=["GET"], strict_slashes=False)
@require_authenticated_user
def get_token(token_id):
    """Lookup token data for a specific token in the application auth database.

        :type token_id: str
        :param token_id: Token identifier
        :rtype: tuple
        :return: token data dictionary, status code
        """

    client_data = g.client_data

    if not valid_token_id(token_id):
        raise MalformedTokenIdException

    token = current_app.auth_db.lookup_token(token_id)

    if token is None:
        raise TokenNotFoundException
    if not isinstance(token, Token):
        raise InternalServerErrorException("auth_db.lookup_token did not return a token object")

    if "admin" not in client_data.roles and token.client_id != client_data.client_id:
        raise InadequateRolesException("Cannot lookup a token which you do not own")

    return json.dumps(token.to_dict()), 200, _JSON_HEADER


@auth.route("/tokens/<token_id>", methods=["DELETE"], strict_slashes=False)
@require_authenticated_user
def delete_token(token_id):
    """Revoke a specific token in the application auth database.

       :type token_id: str
       :param token_id: Token identifier
       :rtype: tuple
       :return: None, status code
       """

    client_data = g.client_data
    if not valid_token_id(token_id):
        raise MalformedTokenIdException

    token = current_app.auth_db.lookup_token(token_id)

    if token is None:
        raise TokenNotFoundException
    if not isinstance(token, Token):
        raise InternalServerErrorException("auth_db.lookup_token did not return a token object")

    if "admin" in client_data.roles:
        current_app.auth_db.revoke_token(token_id)
    else:
        if token.client_id != client_data.client_id:
            raise InadequateRolesException("Cannot revoke a token which you do not own")
        current_app.auth_db.revoke_token(token_id)
    return "", 204


@auth.route("/clients", methods=["GET"], strict_slashes=False)
@require_authenticated_user
def get_current_client():
    """Return client data for requesting client

    """
    client_id = g.client_data.client_id

    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException

    client_data = current_app.auth_provider.get_client(client_id)
    if not client_data or not isinstance(client_data, ClientData):
        raise NotFoundException("Client not found")

    return json.dumps(client_data.to_dict()), 200, _JSON_HEADER


@auth.route("/clients", methods=["POST"], strict_slashes=False)
@require_authenticated_user
def client_self_update():
    """Allow a client to update their client in the application.

        Allows a client to change certain attributes of their client
        using the application auth provider. The client of the
        client that is being updated is pulled from the token that
        authenticated the request. This means that you cannot update
        the client for the client with this route, otherwise
        :meth:`client_self_update` will throw an error because the
        `client` kwarg was passed in more than once.

        :rtype: tuple
        :return: updated client, status code, headers
        """
    post_data = request.get_json()
    client_id = g.client_data.client_id

    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException

    client_data = current_app.auth_provider.get_client(client_id)
    if not client_data or not isinstance(client_data, ClientData):
        raise NotFoundException("Client not found")

    client_self_update_package_class = current_app.auth_provider.self_update_client_package_class

    try:
        client_self_update_package = client_self_update_package_class(**post_data)
    except Exception as err:
        raise MalformedProviderPackageException(str(err))

    updated_client = current_app.auth_provider.client_self_update(client_self_update_package, client_id=client_id)

    if isinstance(updated_client, ClientData):
        updated_client = updated_client.to_dict()

    if isinstance(updated_client, dict):
        updated_client = json.dumps(updated_client)
    return updated_client, 200, _JSON_HEADER


@auth.route("/clients/create", methods=["POST"], strict_slashes=False)
@require_authenticated_user
def create_client():
    """Create a new user using the Lowball application auth provider."""

    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException

    post_data = request.get_json()

    create_client_package_class = current_app.auth_provider.create_client_package_class

    try:
        create_client_package = create_client_package_class(**post_data)
    except Exception as err:
        raise MalformedProviderPackageException(str(err))

    client = current_app.auth_provider.create_client(create_client_package)

    if isinstance(client, ClientData):
        client = json.dumps(client.to_dict())

    elif isinstance(client, dict):
        client = json.dumps(client)

    return client, 201, _JSON_HEADER


@auth.route("/clients/register", methods=["POST"], strict_slashes=False)
def client_registration():
    """Self-register a client in the Lowball application.

        Allow a requester with an admin token to create their own
        client with the application auth provider. The client for
        the new client will be the client that is associated to the
        token that authenticated the request. If client is passed
        in the POST body, it is ignored.

        :rtype: tuple
        :return: new client, status code, headers
        """
    post_data = request.get_json()

    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException

    client_self_registration_package_class = current_app.auth_provider.client_registration_package_class

    try:
        client_self_registration_package = client_self_registration_package_class(**post_data)
    except Exception as err:
        raise MalformedProviderPackageException(str(err))

    new_client_data = current_app.auth_provider.client_self_register(client_self_registration_package)
    if isinstance(new_client_data, ClientData):
        new_client_data = new_client_data.to_dict()

    if isinstance(new_client_data, dict):
        new_client_data = json.dumps(new_client_data)
    return new_client_data, 201, _JSON_HEADER


@auth.route("/clients/all", methods=["GET"], strict_slashes=False)
@require_admin
def get_all_clients():
    """get listing of all clients in the system. filter by roles and client_ids

    """
    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException
    roles = request.args.getlist("roles")
    clients = current_app.auth_provider.list_clients()

    if not isinstance(clients, list) or not all(isinstance(client, ClientData) for client in clients):
        raise ListClientsInvalidReturnTypeException

    if roles:
        clients = [client for client in clients if any(role in roles for role in client.roles)]

    return json.dumps([client.to_dict() for client in clients]), 200, _JSON_HEADER


@auth.route("/clients/<client_id>", methods=["GET"], strict_slashes=False)
@require_admin
def get_client(client_id):
    """Get data for the specified user.

           :type client_id: str
           :param client_id: The client_id to get data for
           :rtype: tuple
           :return: user data dictionary, status code, json content header
           """

    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException

    client = current_app.auth_provider.get_client(client_id)

    if client is None:
        raise NotFoundException(description=f"client_id '{client_id}' not found")

    if not isinstance(client, ClientData):
        raise InternalServerErrorException("auth_provider.get_client did not return a client data object")

    return json.dumps(client.to_dict()), 200, _JSON_HEADER


@auth.route("/clients/<client_id>", methods=["POST"], strict_slashes=False)
@require_admin
def update_client(client_id):
    """Update information for the specified user.

        This route simply takes whatever is in the PATCH body and
        passed it into the auth provider instance's :meth:`update_client`
        method.

        :type client_id: str
        :param client_id: The client to update.
        :rtype: tuple
        :return: updated user, status code, headers
        """

    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException

    patch_body = request.get_json()
    client = current_app.auth_provider.get_client(client_id)

    if client is None:
        raise NotFoundException(description=f"client_id '{client_id}' not found")
    update_client_package_class = current_app.auth_provider.update_client_package_class

    try:
        update_client_package = update_client_package_class(**patch_body)
    except Exception as err:
        raise MalformedProviderPackageException(str(err))

    client = current_app.auth_provider.update_client(update_client_package, client_id)
    if isinstance(client, ClientData):
        client = json.dumps(client.to_dict())

    elif isinstance(client, dict):
        client = json.dumps(client)

    return client, 200, _JSON_HEADER


@auth.route("/clients/<client_id>", methods=["DELETE"], strict_slashes=False)
@require_admin
def delete_client(client_id):
    """Delete a user from the Lowball application auth provider."""
    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException
    client = current_app.auth_provider.get_client(client_id)

    if client is None:
        raise NotFoundException(description=f"client_id '{client_id}' not found")
    current_app.auth_provider.delete_client(client_id)
    return "", 204


@auth.route("/clients/<client_id>/enable", methods=["POST"], strict_slashes=False)
@require_admin
def enable_client(client_id):
    """Enable a user using the Lowball application auth provider."""
    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException
    client = current_app.auth_provider.get_client(client_id)

    if client is None:
        raise NotFoundException(description=f"client_id '{client_id}' not found")
    current_app.auth_provider.enable_client(client_id)
    return "", 204


@auth.route("/clients/<client_id>/disable", methods=["POST"], strict_slashes=False)
@require_admin
def disable_client(client_id):
    """Disable a user using the Lowball application auth provider."""
    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException
    client = current_app.auth_provider.get_client(client_id)
    if client is None:
        raise NotFoundException(description=f"client_id '{client_id}' not found")
    current_app.auth_provider.disable_client(client_id)
    return "", 204


@auth.route("/clients/<client_id>/roles", methods=["DELETE"], strict_slashes=False)
@require_admin
def remove_client_roles(client_id):
    """remove all roles from the specified client

    """
    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException

    client = current_app.auth_provider.get_client(client_id)
    if client is None:
        raise NotFoundException(description=f"client_id '{client_id}' not found in auth provider")

    current_app.auth_provider.delete_roles(client_id, client.roles)

    return "", 204


@auth.route("/clients/<client_id>/roles/<role>", methods=["DELETE"], strict_slashes=False)
@require_admin
def remove_client_role(client_id, role):
    """remove the specified role from the specified client

    """
    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException
    client = current_app.auth_provider.get_client(client_id)
    if client is None:
        raise NotFoundException(description=f"client_id '{client_id}' not found in auth provider")

    current_app.auth_provider.delete_roles(client_id, [role])

    return "", 204


@auth.route("/clients/<client_id>/roles/<role>", methods=["POST"], strict_slashes=False)
@require_admin
def add_client_role(client_id, role):
    """add the specified role to the specified client

    """
    if current_app.auth_provider is None:
        raise AuthenticationNotInitializedException

    client = current_app.auth_provider.get_client(client_id)
    if client is None:
        raise NotFoundException(description=f"client_id '{client_id}' not found in auth provider")

    current_app.auth_provider.add_roles(client_id, [role])

    return "", 204

