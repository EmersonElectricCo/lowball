.. _authentication-providers:

Authentication Providers
########################

Lowball Authentication Providers are the interface for your application(s) to the
`Identity Provider <https://en.wikipedia.org/wiki/Identity_provider>`_ of your choice.

Currently, lowball only supports one Authentication Provider at a time for an application.

.. _available-providers:

Available Authentication Providers
***********************************

The following are known existing lowball Authentication Providers. If you have written one and would like it included,
please submit a PR or contact us to have it added!

.. list-table:: Available Authentication Providers
   :widths: auto

   * - :ref:`builtin-provider`
     - Builtin Provider to the lowball library useful in a development environment.
   * - `lowball-ldap-authprovider <https://github.com/EmersonElectricCo/lowball-ldap-authprovider>`_
     - Utilize your existing LDAP / Active Directory system as your Authentication Provider.

.. toctree::
   :hidden:
   :maxdepth: 3

   builtins/builtinbasicauthprovider

Implementing Your Own Authentication Provider
*********************************************

Lowball allows you to define your own Authentication Provider and use that Identity Provider in your applications /
ecosystem. Let's walk through the process of how to implement one.

Implementing an Authentication Provider starts off by implementing the subclass of `AuthProvider`


.. code-block:: python

    from lowball.models.provider_models.auth_provider import AuthProvider

    class MyCustomAuthProvider(AuthProvider):
        def __init__(self, **kwargs):
            super(MyCustomAuthProvider, self).__init__(**kwargs)
            ...


You can pass anything you want into the `__init__` of either class. The top level class is yours to define however you
want, and the base class `__init__` doesn't set any attributes or run any methods.

Required Methods
================

A valid implementation of `AuthProvider` `must` implement the following methods:

`authenticate`
  This is the method that will be used to authenticate by accepting an `AuthPackage`. How this occurs is
  dependent on the implementation and requirements of the authentication Identity Provider, but this method `must`
  return an instance of `ClientData`

`auth_package_class`
  This is an abstract property that is intended to define the type of authentication package that `authenticate` accepts.
  This should return the class signature of your implementation, `not` an actual instance of the class. For more
  information see `AuthPackage`


Optional Methods
================

The following methods are optional for implementation by the developer. For clarity, any of these
implementations would be managing the chosen Identity Provider from lowball.

`initialized`
  This is used by lowball to determine if the provider is ready to provide authentication services for the application.
  It is a `@property` of the class and should be designed as such. By default, this returns `True`.

`create_client_package_class`
  This is an abstract property that is intended to define the type of data need to create a user by an admin.
  This should return the class signature of your implementation, `not` an actual instance of the class. For more
  information see `CreateClientPackage`

`client_registration_package_class`
  This is an abstract property that is intended to define the type of data needed for a user to self-register.
  This should return the class signature of your implementation, `not` an actual instance of the class. For more
  information see `ClientRegistrationPackage`

`update_client_package_class`
  This is an abstract property that is intended to define the type of data updating a user as an admin.
  This should return the class signature of your implementation, `not` an actual instance of the class. For more
  information see `SelfUpdateClientPackage`

`self_update_client_package_class`
  This is an abstract property that is intended to define the type of data updating a user as a user accepts.
  This should return the class signature of your implementation, `not` an actual instance of the class. For more
  information see `SelfUpdateClientPackage`

`create_client`
  Method that can be used to create a client in the Identity Provider. Accepts a `CreateClientPackage`.

`client_self_register`
  Method that can be used to self-register a client in the Identity Provider. Accepts a `ClientRegistrationPackage`.

`enable_client`
  Used to activate a client in the Identity Provider. It has no requirements on return.

`disable_client`
  Used to deactivate a client in the Identity Provider. It has no requirements on return.

`delete_client`
  Used to remove a client from the Identity Provider. It has no requirements for its return.

`add_roles`
  Used to add a list of roles / group-like attributes to a specific client in the Identity Provider. It takes a
  `client_id` and a list of the roles to assign. It has no requirements for its return value.

`delete_roles`
  Used to remove roles / group-like attributes from a specific client in the Identity Provider. It takes a `client_id`
  and a list of the roles to remove. It has no requirements for its return value.

`update_client`
  Used by an admin to update attributes of an existing client registered in the Identity Provider. It takes a
  `client_id` and any arguments needed to update the client properly. It should return a `ClientData` Object

`client_self_update`
  Identical to `update_client`, but a separate interface was established to allow for a distinction between an admin
  updating a client and a client updating themself in the system.

`list_clients`
  Used to list all the clients who are registered in the system. The return value from this method must be a list of
  `ClientData` Objects.

`get_client`
  Get details on the specified `client_id` provided. It must return an instance of a `ClientData` Object or
  `ClientData` subclass representing the requested `client_id` and associated roles. This method must be implemented
  to enable non admin clients to create their own tokens without going through the typical login process,
  in addition to any features involved with accessing client information.

ClientData Object
=================

For methods that are supposed to return a `ClientData` object, it is best practice, and in many cases required that the
result be in the form of a `ClientData` object, either as the base class or a subclass.

The base class takes two arguments to become initialized:

`client_id`
  a string representing the identifier for this user. This argument is required.

`roles`:
  a list of roles the user has in the system. This must be a list of strings, and is required.

The class also has a method, `to_dict` which will return a dictionary representation of the `ClientData` object. For the
base class, this is something like this:

.. code-block:: json

    {
      "client_id": "client",
      "roles": ["role1", "role2", "role3"]
    }


**Custom Client Objects**

If you want to extend the functionality of the `ClientData` class, simply subclass it in your custom object. This custom
class will still need `client_id` and `roles` passed in at `__init__` to instantiate, but you may add other arguments if
you should choose to do so.

It is recommended that if you do implement new attributes for your custom class that you modify the `to_dict` method in
this manner:

.. code-block:: python

    def to_dict(self):
        base_dict = super(CustomUser, self).to_dict()
        base_dict.update({
            # this is where you add your
            # custom attributes
        })
        return base_dict


AuthPackage
===========

`AuthPackage` is an abstract class that is to be implemented by the Authentication Provider. This class is used to
define what data the Authentication Provider expects to be given when a client initially authenticates and requests a
token.

The top level objects from the `POST` request to the `/builtin/auth` endpoint will be directly mapped to `AuthPackage`
class `__init__`.

For example if the `AuthProvider` expects a `username` and `password` then the implementation of the `AuthPackage` would
look something like this:

.. code-block:: python

    from lowball.models.provider_models.auth_provider import AuthPackage

    class MyAuthPackage(AuthPackage):

        def __init__(self, username, password, **kwargs):
            super(DefaultAuthPackage, self).__init__(**kwargs)

The request body sent to `/builtin/auth` would need to come in the following form

.. code-block:: json

    {
      "username": "the_user",
      "password": "MySuperComplexPassword"
    }

This would then be mapped to an instance of `MyAuthPackage` and given to the Authentication Provider's `authenticate`
method.

CreateClientPackage
===================

`CreateClientPackage` is an optional abstract class that is to be implemented by the Authentication Provider. This class
is used to define what data the Authentication Provider expects to be given when an admin is creating a user in the
Authentication Provider.

The top level objects from the `POST` request to the `/builtin/auth/create` endpoint will be directly mapped to
`CreateClientPackage` class `__init__`.

ClientRegistrationPackage
=========================

`ClientRegistrationPackage` is an optional abstract class that is to be implemented by the Authentication Provider. This
class is used to define what data the Authentication Provider expects to be given when a user is self-registering with
the Authentication Provider.

The top level objects from the `POST` request to the `/builtin/auth/register` endpoint will be directly mapped to
`ClientRegistrationPackage` class `__init__`.


UpdateClientPackage
===================

`UpdateClientPackage` is an optional abstract class that is to be implemented by the Authentication Provider. This class
is used to define what data the Authentication Provider expects to be given when an admin is updating attributes of a
client in the Authentication Provider.

The top level objects from the `POST` request to the `/builtin/auth/clients/<client_id>` endpoint will be directly
mapped to `UpdateClientPackage` class `__init__`.


SelfUpdateClientPackage
=======================

`SelfUpdateClientPackage` is an optional abstract class that is to be implemented by the Authentication Provider. This
class is used to define what data the Authentication Provider expects to be given when the client is updating attributes
of themselves in the Authentication Provider.

The top level objects from the `POST` request to the `/builtin/auth/clients` endpoint will be directly mapped to
`SelfUpdateClientPackage` class `__init__`.


Using Your Custom Authentication Provider
=========================================

Once you have created your custom Authentication Provider class, you can use it in your lowball application by passing
the class signature to the `auth_provider` argument of the `__init__` of the lowball application:

.. code-block:: python

    app = Lowball(config=conf, auth_provider=MyCustomAuthProvider)


Do not pass an instance of the class at `__init__`. This will fail as lowball is responsible for initializing the class
and will map the object the configuration options from the `auth_provider` section of the to the `__init__` of the
custom Authentication Provider class.

For example, if your custom auth provider takes three arguments on `__init__` such as `client_id`, `password`, and
`hostname`, then the `auth_provider` section of your config should look something like this:

.. code-block:: yaml

    auth_provider:
      client_id: user
      password: keepitsecretkeepitsafe
      hostname: host.domain.com


These values will be mapped automatically into the `__init___` of your custom class when you instantiate your lowball
application.