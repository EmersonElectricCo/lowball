.. _authentication-databases:

Authentication Databases
########################

Lowball leverages the concept of an Authentication Database to manage the authentication tokens issued by your
application(s). The Authentication Database interface serves as a simple template for interacting with the storage
mechanism of your choice e.g. local storage, a traditional database, in memory storage, etc.

The Auth Database does `*DOES NOT*` store the actual tokens. Rather, it tracks valid tokens and their metadata.

Currently, lowball only supports one Authentication Database at a time for an application.

.. _available-databases:

Available Authentication Databases
**********************************

The following are known-existing lowball Authentication Databases. If you have written one and would like it included,
please submit a PR or contact us to have it added!

.. list-table:: Available Authentication Databases
   :widths: auto

   * - :ref:`builtin-authdatabase`
     - Builtin Auth Database to the lowball library for use in your development environment.
   * - `lowball-arango-authdb <https://github.com/EmersonElectricCo/lowball-arango-authdb>`_
     - Utilize an `ArangoDB <https://arangodb.com>`_ as your Authentication Database backend

.. toctree::
   :hidden:
   :maxdepth: 3

   builtins/builtinbasicauthdatabase

Implementing Your Own Authentication Database
*********************************************

Lowball allows you to define your own Authentication Database to use in your ecosystem. Let's walk through the process
of how to implement one.

Implementing an Authentication Database starts off by implementing the subclass of `AuthDatabase`.

.. code-block:: python

    from lowball.models.provider_models.auth_db import AuthDatabase


    class CustomAuthDatabase(AuthDatabase):
        def __init__(self, **kwargs):
            super(CustomAuthDatabase, self).__init__(**kwargs)
            ...


You can pass anything you want into the `__init__` of either class. The top level class is yours to define however you
want, and the base class `__init__` doesn't set any attributes or run any methods.

Required Methods
================

A valid implementation of `AuthDatabase` `*must*` implement the following methods:


`add_token`
  Used to add a valid token to the Authentication Database. It takes one argument: `token_object`, which `*must*` be a
  `Token` object.

`lookup_token`
  Used to lookup a single token in the database using a `token_id`. It should return a `Token` object.

`revoke_token`
  Used to revoke / delete the token with the supplied `token_id` from the database.

`list_tokens`
  Used to return a list of all the tokens in the database. Each item in the returned list should be a `Token` object.

`list_tokens_by_client_id`
  Used to look up all tokens associated with a given user. Takes single argument, `client_id`. The output should be a
  `list` of `Token` objects.

`list_tokens_by_role`
  Similar to `list_tokens_by_client_id`; the returned tokens should be all tokens associated with the requested role.
  Takes single argument `role`. The output should be a `list` of `Token` objects.

`cleanup_tokens`
  Is meant to remove all expired tokens from the database.

`revoke_all`
  Deletes all tokens from the database


Token Objects
=============

Authentication is carried out in lowball through the use of JSON Web Tokens (JWT). The object representation of these
inside of lowball are `Token` objects. These objects are meant to be the return values of several class methods in the
codebase that create, update, etc. tokens in the application.

These tokens `*do not*` actually store the signed JWT, but rather house the data that is encoded in the JWT. These
objects take a number of arguments to be initialized (all of which are required):

`cid`
  A string representing the client that the token is assigned to.

`r`
  A list of roles that this token is authorized for. These roles must all be strings.

`cts`
  A datetime string representing when the token was created. The format for the datetime string is `%Y-%m-%d %H:%M:%S`.

`ets`
  A datetime string representing when the token will not longer be a valid token for authentication. The format for the
  datetime string is `%Y-%m-%d %H:%M:%S`.

`rcid`
  A string representing the client who requested the particular token.

`tid`
  A UUID of the token that is used to identify it in the application. The `[a-zA-Z0-9]{16}`


`Token` objects have the method, `to_dict` that is used to return a dictionary representation of the `Token` object.
When called, it will return something like this:

.. code-block:: json

    {
      "cid": "user",
      "r": ["role1", "role2", "role3"],
      "cts": "2020-01-01 00:00:00.0000",
      "ets": "2020-02-01 00:00:00.0000",
      "rcid": "issuing_user",
      "tid": "7d760e6d-185a-41f1-b9de-8b87033c5435"
    }


Using Your Custom Authentication Database
=========================================

.. code-block:: python

    app = Lowball(config=conf, auth_database=CustomAuthDatabase)


**Do not pass an instance of the class at** `__init__`. This will fail because the lowball `__init__` will map the
object from the `auth_db` section of the to the `__init__` of the custom class.

For example, if your custom Authentication Database takes three arguments on `__init__` such as `username`, `password`,
and `database_collection`, then the `auth_db` section of your config should look something like this:

.. code-block:: yaml

    auth_db:
      username: user
      password: keepitsecretkeepitsafe
      database_collection: tokens


These values will be mapped automatically into the `__init__` of your custom class when you instantiate your lowball
application.
