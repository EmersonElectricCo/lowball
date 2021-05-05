.. _builtin-authdatabase:

Builtin Basic Authentication Database
######################################

The builtin Authentication Database makes use of file-system storage for tokens. It is meant to be minimal, have no
external dependencies and help a developer get up and running quickly. It could be used in a small production
environment that has limited authentication needs.


Configuration
*************

No configuration is required for this Authentication Database but it has one optional item.

`token_path`
  This is the path on disk where the token data will be stored. It defaults to `/var/lib/lowball/authentication/tokens`

**Example Config**

.. code-block:: yaml

    token_path: "/app/authentication/tokens"




