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

Please make sure to extend your configurations from `BaseConfig` (only if you are sure what you are doing. Recommended way is to use the environment variables for the configuration.)

```python
from flaskoidc import FlaskOIDC
from flaskoidc.config import BaseConfig

# Custom configuration class, a subclass of BaseConfig
CustomConfig(BaseConfig):
    DEBUG = True

app = FlaskOIDC(__name__)
app.config.from_object(CustomConfig)

```

Following environment variables along with their default values are available for `flaskoidc`. 

```python
# Flask `SECRET_KEY` config value
FLASK_OIDC_SECRET_KEY: 'base-flask-oidc-secret-key'

# Comma separated string of URLs which should be exposed without authentication, else all request will be authenticated.
FLASK_OIDC_WHITELISTED_ENDPOINTS: "status,healthcheck,health"

FLASK_OIDC_LOG_DATE_FORMAT: '%Y-%m-%dT%H:%M:%S%z'
FLASK_OIDC_LOG_LEVEL: 'INFO'
```

This package relies purely on the `flask-oidc` package. All the configurations variable for flask-oidc
can be set using the `ENVIRONMENT VARIABLES`
[Flask-OIDC COnfiguration](https://flask-oidc.readthedocs.io/en/latest/#settings-reference)

Following are some of the examples: 
```python
# Path of your configuration file. (default value assumes you have a `config/client_secrets.json` available.
# Below is the sample file you can use
OIDC_CLIENT_SECRETS: 'config/client_secrets.json'

OVERWRITE_REDIRECT_URI: False

OIDC_CALLBACK_ROUTE: '/oidc_callback'
```

Similar to Flask-OIDC, you can also set the config variables specific to [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/en/2.x/config/) using the same key as the environment variables.
```python
# Details about this below in the "Session Management" section.
SQLALCHEMY_DATABASE_URI: 'sqlite:///sessions.db'
```

And same goes for [Flask-Session](https://flask-session.readthedocs.io/en/latest/#configuration).
```python
# Specifies which type of session interface to use.
SESSION_TYPE: 'sqlite:///sessions.db'
```


#### (SAMPLE) Client Secrets Files:
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
        "token_introspection_uri": "http://localhost:8080/auth/realms/master/protocol/openid-connect/token/introspect",
    }
}
```

`client_secrets_google.json`
```json
{
    "web": {
        "issuer": "https://accounts.google.com",
        "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
        "client_id": "my-application-id-in-google",
        "client_secret": "my-application-secret-in-google",
        "userinfo_uri": "https://openidconnect.googleapis.com/v1/userinfo",
        "token_uri": "https://oauth2.googleapis.com/token",
        "token_introspection_uri": "https://oauth2.googleapis.com/tokeninfo"
    }
}

```

## Session Management
This extension uses SQLAlchemy to hold the sessions of the users. Flask OIDC saves the sessions in memory by default 
which is very vulnerable. This adds the support of custom session store. 
By default the path of database is `sqlite:///sessions.db` and can be configured using the environment variable `SQLALCHEMY_DATABASE_URI`


## ToDo
- Add exmaple application
- Configurable token validation (local vs server side on each request)
- Token Refresh
- Add logging

