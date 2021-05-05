##########
Quickstart
##########

This guide will lead you through the basics of launching a lowball service using the built in authentication provider
and authentication database.

The intent of this guide is to give you a quick introduction to the concepts lowball implements.

.. note::
    The authentication database and provider used in this tutorial are the defaults for lowball. They are great for
    use in a development environment. However, it is highly recommend to only use these for development and NOT in a
    production environment. Once you are ready to deploy your application(s) we highly recommend changing out the
    authentication components for other :ref:`available-providers` and :ref:`available-databases`.


Before You Begin
****************

Be sure you have installed the lowball library through your method of choice. For more detail see :ref:`installing-lowball`


Basic lowball App
******************

A minimal lowball service looks like this:

.. code-block:: python

    from lowball import Lowball, require_admin

    app = Lowball()

    @app.route("/hello", methods=["GET"])
    @require_admin
    def hello_world():
        return {"hello":"world"}, 200


    if __name__ == '__main__':
        app.run()


That's it, if we were to run this application with the below command, we would have a lowball application running using
the builtin default authentication provider and authentication database. These components enable to us limit access to
our hello world app to only users with the admin role assigned.

.. code-block:: bash

    python3 app.py


To to access our `/hello` endpoint we will need to have a token with the `admin` role associated with it. This can be
achieved by making a request to the lowball builtin `/builtins/auth` endpoint to get a token. Because we are using the builtin
authentication provider with the default config we do this via the following curl request:

.. code-block:: bash

    curl -i -X POST -H "Content-Type: application/json" http://localhost:5000/builtins/auth --data "{\"username\": \"admin\", \"password\": \"nimda\"}"

which will return a similar response to:

.. code-block:: json

    {
      "token": "eyJ0e...jjk",
      "token_data": {
        "cid": "admin",
        "r": [
          "admin"
        ],
        "cts": "2021-04-28 14:44:59",
        "ets": "2021-04-28 15:44:59",
        "rcid": "admin",
        "tid": "SbH7opPxReMbyZZr"
      }
    }

Our successful call to the auth endpoint returned a few things. First and foremost is the token which is what we will use
in subsequent calls to other endpoints with RBAC controls associated with them.

In addition to the token itself, we we are given some additional meta data describing the token. This data is what is
stored in the authentication database. No actual authentication data is stored in the database including the tokens
themselves, passwords, secrets, etc.

`cid`
  Client ID associated with the token. This is the "user" according to the authentication provider.

`r`
  An array of roles issued to the token

`cts`
  Creation / issue time of the token

`ets`
  Expiration time of the token

`rcid`
  Requesting Client ID or the Client ID that requested the token. This will either be the same as the cid or an administrator
  that issued the token on the clients behalf.

`tid`
  Unique token ID

.. note::
    The default password for the builtin authentication provider is `nimba`. It is highly recommend to overwrite this
    password. See :ref:`builtin-provider` for best practices.

Now that we have the token, we can now call our hello endpoint with the following curl command:

.. code-block:: bash

    curl -i -H "Authorization: Bearer eyJ0e...jjk" http://localhost:5000/hello

.. code-block:: json

    {
      "hello" : "world"
    }

That's it! You now have the basics for getting started with endpoint based RBAC controls and lowball. Read on to learn
details on the authentication providers, authentication databases, configs, and more...