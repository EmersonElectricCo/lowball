Welcome to lowball's documentation!
===================================

**What is it?**
Lowball is designed to add simple endpoint level RBAC to your Flask based API services.

**What does it do?**
Lowball is, at its core, a wrapper around `Flask <https://github.com/pallets/flask>`_, designed to add authentication
and permission management features to Flask's already powerful and modular implementation. Lowball was developed to
support three key needs:

1) Easy to use route level RBAC controls.
2) Abstracted authentication providers and databases for easier integration with your operating environment.
3) Ecosystem of 1 - n microservices leveraging a common authentication authority.

Lowball implements this with three components

1) :ref:`rbac-enforcement`
2) :ref:`authentication-providers`
3) :ref:`authentication-databases`

Together, these components allow a developer to produce 1 - n microservices that are able to integrate with your existing
authentication infrastructure and utilize database technologies of your choice.

Continue reading to find out more!

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   installation
   quickstart
   routerbacenforcement
   includedroutes
   authenticationproviders
   authenticationdatabases
   configs
   logging




