.. _rbac-enforcement:

Route RBAC Enforcement
######################

Lowball implements role-based access controls (RBAC) at the endpoint level via a handful of route decorators that make it easy
for you as a service developer to add RBAC enforcement at the endpoint level without disrupting the structure of your
project.

The enforcement decorators use the token's declared roles to validate the authorization for the transaction.

The following sections describe the various RBAC decorators and their function.

Require Authenticated User
**************************

`require_authenticated_user` allows access to an endpoint for any user who provides a valid token regardless of the
token's roles.

**Example**

.. code-block:: python

    from lowball import Lowball, require_authenticated_user
    ...
    @app.route("/launch", methods=["GET"])
    @require_authenticated_user
    def view_upcoming_launches():
        return {...}, 200

In the above example, any valid token will be able to access the endpoint.

Require Any of These Roles
**************************

`require_any_of_these_roles` allows any token with at least one of the roles in the provided list access to the given
endpoint.

**Example**

.. code-block:: python

    from lowball import Lowball, require_any_of_these_roles
    ...
    @app.route("/launch/<id>", methods=["GET"])
    @require_any_of_these_roles(['lead','manager','audit'])
    def view_launch_details(id):
        return {...}, 200

In the above example, any token that has at least a `lead`, `manager` or `audit` role granted to it will be allowed to
access the endpoint.

Require All of These Roles
**************************

`require_all_of_these_roles` allows only a token possessing all of the specified roles to access the endpoint.

**Example**

.. code-block:: python

    from lowball import Lowball, require_all_of_these_roles
    ...
    @app.route("/launch", methods=["POST"])
    @require_all_of_these_roles(['manager','certified_specialist'])
    def launch_the_rocket():
        return {"hello":"world"}, 200

In the above example, only a token that has both a `manager` and `certified_specialist` role assigned to it will be able
to access the endpoint.


Require Admin
*************

`require_admin` is a convenience decorator for requiring a token to have the `admin` role assigned to it. This is the
equivalent of:

.. code-block:: python

    @require_all_of_these_roles(['admin'])

**Example**

.. code-block:: python

    from lowball import Lowball, require_admin
    ...
    @app.route("/reboot", methods=["POST"])
    @require_admin
    def reboot_the_system():
        return {...}, 200