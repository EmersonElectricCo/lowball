<h1 align="center">Lowball</h1>
<p align="center">
Lowball is a python3 Flask wrapper designed to add endpoint level RBAC to your API Services with an easy integration interface to authentication mechanisms of your choice.
</p>

***
## Overview
Lowball is, at its core, a wrapper around [Flask](https://github.com/pallets/flask), designed to add authentication and 
permission management features to Flask's already powerful and modular implementation. Lowball was developed to support three key needs:


1) Easy to use route level RBAC controls.
2) Abstracted authentication providers and databases for easier integration with operating environment.
3) Make it easy to have 1 - n microservices coexisting with the same framework. 


## Installation
### Using pip
`pip install lowball`

### From Source
```shell
git clone https://github.com/EmersonElectricCo/lowball
cd ./lowball
pip install -r requirements.txt
python3 setup.py install
```


## A Simple Example
Lowball comes prepared to work out of the box, so getting a simple application up and running is trivial. The following 
example implements a single route that requires an authenticated user with a role of `admin` for access.

```python
from lowball import Lowball, config_from_object, require_admin

conf = {
    "meta": {
        "name": "APP",
        "base_route": "/app",
        "description": "description of application goes here",
    },
    "authentication": {
        "default_token_life": 3600,
        "max_token_life":  7200
    }
}

app = Lowball(config=config_from_object(conf))


@app.route("/admin/route", methods=["GET"])
@require_admin
def admin_route():
    return "some data", 200

if __name__ == '__main__':
    app.run()
```

Check [the usage docs](./docs/index.md) for more in-depth explanations of components.

## Contributing
Please see our [contribution guide]()

## Links
- [Issues](https://github.com/EmersonElectricCo/lowball/issues)

