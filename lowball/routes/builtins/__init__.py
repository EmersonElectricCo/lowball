"""
LOWBALL BUILTIN ROUTES

/builtins

- /auth - post/del/get (login/logout/current token info)

- /auth/tokens - get (current user all), post (create token), del (delete all current user tokens)

- /auth/tokens/all - get (all tokens in system) Admin, delete (revoke all tokens in system) (query params for client/roles/etc...)

- /auth/tokens/cleanup - post (admin) cleanup expired tokens

- /auth/tokens/<token id> - get/del ( admin can view/delete all, non admin only own)

- /auth/clients - get/post (get get self client, self update)

- /auth/clients/create - post (admin) create client

- /auth/clients/register - post client self registration

- /auth/clients/all get (admin) get all clients in system

- /auth/clients/<client_id> - (admin) get/delete/post (user info, delete user, update user)

- /auth/clients/<client_id>/roles delete (admin) /<role> - post/delete admin add/remove role from client

-/status

-/
"""

from .auth import auth
from .status import status