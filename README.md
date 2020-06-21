# FlaskOIDC
[![PyPI version](https://badge.fury.io/py/flaskoidc.svg)](https://badge.fury.io/py/flaskoidc)
[![License](http://img.shields.io/:license-Apache%202-blue.svg)](LICENSE)

A wrapper of Flask with pre-configured OIDC support. Ideal for microservices architecture, each request will be authenticated using Flask's `before_request` middleware. Necassary endpoints can be whitelisted using an environment variable `FLASK_OIDC_WHITELISTED_ENDPOINTS`. 

## Usage:

After simply installing the flaskoidc you can simply use it like below:

```python
from flaskoidc import FlaskOIDC
app = FlaskOIDC(__name__)
``` 

## Configurations:

Please make sure to extend your configurations from `BaseConfig`.

```python
from flaskoidc import FlaskOIDC
from flaskoidc.config import BaseConfig

# Custom configuration class, a subclass of BaseConfig
CustomConfig(BaseConfig):
    DEBUG = True

app = FlaskOIDC(__name__)
app.config.from_object(CustomConfig)

```

Following environment variables along with their default values are available and must be set based on the settings. 

```python
# Flask `SECRET_KEY` config value
FLASK_OIDC_SECRET_KEY: 'base-flask-oidc-secret-key'

# Comma separated string of URLs which should be exposed without authentication, else all request will be authenticated.
FLASK_OIDC_WHITELISTED_ENDPOINTS: "status,healthcheck,health"

# Path of your configuration file. (default value assumes you have a `config/client_secrets.json` available.
FLASK_OIDC_CLIENT_SECRETS: 'config/client_secrets.json'

# Details about this below in the "Session Management" section.
FLASK_OIDC_SQLALCHEMY_DATABASE_URI: 'sqlite:///sessions.db'
```

### Client Secrets File:
The client secrets file looks like this:

`client_secrets.json`
```json
{
    "web": {
        "issuer": "http://localhost:8080/auth/realms/master",
        "issuer_admin": "http://localhost:8080/auth/admin/realms/master",
        "auth_uri": "http://localhost:8080/auth/realms/master/protocol/openid-connect/auth",
        "client_id": "my-application-id",
        "client_secret": "my-application-secret-in-keycloak",
        "userinfo_uri": "http://localhost:8080/auth/realms/master/protocol/openid-connect/userinfo",
        "token_uri": "http://localhost:8080/auth/realms/master/protocol/openid-connect/token",
        "token_introspection_uri": "http://localhost:8080/auth/realms/master/protocol/openid-connect/token/introspect"
    }
}
```

## Session Management
This extension uses SQLAlchemy to hold the sessions of the users. Flask OIDC saves the sessions in memory by default 
which is very vulnerable. This adds the support of custom session store. 
By default the path of database is `sqlite:///sessions.db` and can be configured using the environment variable `FLASK_OIDC_SQLALCHEMY_DATABASE_URI`


## ToDo
- Add exmaple application
- Configurable token validation (local vs server side on each request)
- Token Refresh
- Add logging

