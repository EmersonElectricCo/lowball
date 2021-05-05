<h1 align="center">Lowball</h1>
<p align="center">
Lowball is designed to add simple endpoint level RBAC to your Flask based API services.
</p>


## Overview
Lowball is, at its core, a wrapper around Flask, designed to add authentication
and permission management features to Flask's already powerful and modular implementation. Lowball was developed to
support three key needs:

1) Easy to use route level RBAC controls.
2) Abstracted authentication providers and databases for easier integration with your operating environment.
3) Ecosystem of 1 - n microservices leveraging a common authentication authority.


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
A minimal lowball service looks like this

```python
from lowball import Lowball, require_admin

app = Lowball()

@app.route("/hello", methods=["GET"])
@require_admin
def hello_world():
    return {"hello":"world"}, 200


if __name__ == '__main__':
    app.run()
```

Check [docs](https://lowball.readthedocs.io/en/stable/) for more in-depth explanations of components.


## Links
- [Issues](https://github.com/EmersonElectricCo/lowball/issues)

