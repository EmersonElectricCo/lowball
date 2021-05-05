.. _configuration:

Configs
#######

Lowball configs come in the form of a YAML or JSON file. There are six recognized top-level configuration sections:

`meta`
  Metadata about the application such as description, tags, etc.

`authentication`
  Configs used for the governance of tokens such as max lifetime of a token.

`application`
  Configurations used by the service itself.

`auth_provider`
  All data surrounding the chosen Authentication Provider.

`auth_db`
  All data surrounding the chosen Authentication Database.

`logging`
  All data surrounding the chosen log provider and format.

All configuration values native to lowball have default values and thus have no requirements.

Upon initialization, all configuration values are mapped to the app class variable `lowball_config`, which means that it
can be accessed in the following manner:

**In the Application Itself**

.. code-block:: python

    self.lowball_config


**In a View Function**

.. code-block:: python

    from flask import current_app


    @app.route("/", methods=["GET"])
    def view_func():
        app_config = current_app.lowball_config


Meta Config
************

The `meta` config section is used to define attributes that describe the application. The primary purpose of this data
is exposing it on the `/builtin/status` endpoint. However, like all config items it is made available for use anywhere
in the application. There is one reserved field used by the operation of the application and four reserved fields used
by the status route.

`base_route`
  If provided will be prepended to every route. For example if your have `localhost:5000/hello` and then define a base
  route of `/app` then the full url in operation would be `localhost:5000/app/hello`. This functionality can be useful
  when running the services behind an API Gateway, ingress controller, etc.

`name`
  Simple name of the application.

`description`
  Simple description of your application.

`tags`
  Used to label / tag your application instance.

**Meta Example**

.. code-block:: yaml

    meta:
      name: THE_APP
      base_route: /app
      description: "my super awesome application"
      tags:
        - experimental
        - awesome

Authentication Config
*********************

The `authentication` config used for the governance of tokens in the system. There are three available settings:

`token_secret`
  The token secret is the string used to encrypt / decrypt the JWTs (tokens). It is highly encouraged to set this to a
  secure string of your choosing for anything other than local development. If it is not specified in the config, it
  will default to `CHANGE_ME`.

`default_token_life`
  Specifies the lifetime (in seconds) that a generated token is to be valid, if it is not specified by the requester. If
  a configuration value is not supplied, it will default to 3600 (1 hour).

`max_token_life`
  Specifies the maximum lifetime (in seconds) that can be granted to a token. If a configuration value is not specified
  it will default to 2592000 (~30 days).


.. code-block:: yaml

    authentication:
      default_token_life: 3600
      max_token_life: 7200
      token_secret: "supersecrettokensecret"


Application Config
******************

The `application` config is the place where configs that are specific to the application are meant to be stored. This
could be anything from URLs for external APIs that the service is meant to make requests to, to usernames for databases
that the service pulls data from. Given the nature of this type of data, there is no enforcement on the data that
is contained in this section of the config. All that is necessary is that it be in an object format in the config, so
that it can be read in as a python `dict` object.


Authentication Provider Config
******************************

Configuration values associated with the chosen Authentication Provider. These values are defined by the implementation
of the given provider. See :ref:`available-providers` for further documentation.

Auth Database Config
********************

Configuration values associated with the chosen Authentication Database. These values defined by the implementation of
the given database. See :ref:`available-databases` for further documentation.

Logging Config
**************

Configuration values associated with the chosen Logging Provider. See :ref:`logging` for further documentation.

Reading in Configs
*******************

The configs that lowball uses can be read in using two methods:
1. Directly from a python `dict` using the `config_from_object` builtin method
2. From a JSON or YAML file using the `config_from_file` builtin method

**From an object**

.. code-block:: python

    from lowball import config_from_object

    config = {
       "meta": {
          "name": "APP",
          "base_route": "/app",
          "description": "example to show config reading methods"
       },
       "authentication": {
          "max_token_life": 7200,
          "default_token_life": 3600,
          "token_secret": "supersecrettokensecret"
       },
       "application": {
          "username": "user_of_import"
       },
       "auth_provider": {
          ...
       },
       "auth_db": {
          ...
       },
       "logging": {
          ...
       }
    }

    config_object = config_from_object(config)


**From a JSON File**

`config.json` could look something like this:

.. code-block:: json

    {
       "meta": {
          "name": "APP",
          "base_route": "/app",
          "description": "example to show config reading methods"
       },
       "authentication": {
          "max_token_life": 7200,
          "default_token_life": 3600,
          "token_secret": "supersecrettokensecret"
       },
       "application": {
          "username": "user_of_import"
       },
       "auth_provider": {

       },
       "auth_db": {

       },
       "logging": {

       }
    }


We would read it in like this:

.. code-block:: python

    from lowball import config_from_file

    config_object = config_from_file("./config.json")


**From a YAML File**

`config.yaml` could look something like this:

.. code-block:: yaml

    meta:
      name: APP
      base_route: /app
      description: "description of application goes here"
    authentication:
      default_token_life: 3600
      max_token_life: 7200
      token_secret: "supersecrettokensecret"
    application:
      username: user_of_import
    auth_provider:
      ...
    auth_db:
      ...
    logging:
      ...


We would read it in like this:

.. code-block:: python

    from lowball import config_from_file

    config_object = config_from_file("./config.yaml")
