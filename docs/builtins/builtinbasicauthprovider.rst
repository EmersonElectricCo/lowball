.. _builtin-provider:

Builtin Basic Authentication Provider
######################################

The builtin Authentication Provider is meant to be minimal, have no external dependencies and help a developer get up
and running quickly. It could be used in a small production environment that has limited authentication needs.

It provides a username and password setup with a single `admin` user. The authentication mechanism for this class simply
checks if the `username` and `password` of the provided `AuthPackage` matches the configured username and password. If
they do, then an `AuthData` object is returned with the provided `username` and given the role of `admin`.

Configuration
*************
No configuration is required for this Authentication Provider but uses two optional items.

`username`
  username of the user to be created. Defaults to `admin`.

`password`
  password of the user to be created. Defaults to `nimda`.

**Example Config**

.. code-block:: yaml

    auth_provider:
      username: admin
      password: myComplexPassword

Example Authentication Request
******************************

.. code-block:: bash

    curl -i -X POST -H "Content-Type: application/json" http://localhost:5000/builtins/auth --data "{\"username\": \"admin\", \"password\": \"nimda\"}"
