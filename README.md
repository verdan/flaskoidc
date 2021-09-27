# FlaskOIDC
[![PyPI version](https://badge.fury.io/py/flaskoidc.svg)](https://badge.fury.io/py/flaskoidc)
[![License](http://img.shields.io/:license-Apache%202-blue.svg)](LICENSE)

This package relies purely on the `Authlib` package. [Authlib](https://docs.authlib.org/en/latest/)

A wrapper of Flask with pre-configured OIDC support. Ideal for microservices architecture, each request will be authenticated using Flask's `before_request` middleware. 
Necassary endpoints can be whitelisted using an environment variable `FLASK_OIDC_WHITELISTED_ENDPOINTS`. 

## Installation:
```bash
pip3 install flaskoidc
```


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

Following `ENVIRONMENT VARIABLES` MUST be set to get the OIDC working.

#### FLASK_OIDC_PROVIDER_NAME 
_(default: 'google')_

The name of the OIDC provider, like `google`, `okta`, `keycloak` etc. I have verified this package only for
google, okta and keycloak. Please make sure to open a new issue if any of your OIDC provider is not working.

#### FLASK_OIDC_SCOPES 
_(default: 'openid email profile')_

Scopes required to make your client works with the OIDC provider, separated by a space. 

- OKTA: make sure to add `offline_access` in your scopes in order to get the refresh_token.

#### FLASK_OIDC_USER_ID_FIELD
_(default: 'email')_

Different OIDC providers have different id field for the users. Make sure to adjust this according to what 
your provider returns in the user profile i.e., `id_token`.

#### FLASK_OIDC_CLIENT_ID
_(default: '')_

Client ID that you get once you create a new application on your OIDC provider.

#### FLASK_OIDC_CLIENT_SECRET
_(default: '')_

Client Secret that you get once you create a new application on your OIDC provider.

#### FLASK_OIDC_REDIRECT_URI
_(default: '/auth')_

This is the endpoint that your OIDC provider hits to authenticate against your request. 
This is what you set as one of your REDIRECT URI in the OIDC provider client's settings.  

#### FLASK_OIDC_CONFIG_URL
_(default: '')_

To simplify OIDC implementations and increase flexibility, OpenID Connect allows the use of a "Discovery document," a JSON document found at a well-known location containing key-value pairs which provide details about the OpenID Connect provider's configuration, including the URIs of the authorization, token, revocation, userinfo, and public-keys endpoints.

Discovery Documents may be retrieved from:
- `Google`: https://accounts.google.com/.well-known/openid-configuration
- `OKTA`
  - https://[YOUR_OKTA_DOMAIN]/.well-known/openid-configuration
  - https://[YOUR_OKTA_DOMAIN]/oauth2/[AUTH_SERVER_ID]/.well-known/openid-configuration
- `Auth0`: https://[YOUR_DOMAIN]/.well-known/openid-configuration
- `Keycloak: http://[KEYCLOAK_HOST]:[KEYCLOAK_PORT]/auth/realms/[REALM]/.well-known/openid-configuration


#### FLASK_OIDC_OVERWRITE_REDIRECT_URI
_(default: '/')_
In some cases you may need to redirect to a different endpoint after a successful login. This environment lets you set that endpoint. By default, this redirects to `/`. 

#### FLASK_OIDC_PROVIDER_ADDITIONAL_PARAMETERS_FILE_PATH
_(default: None)_

The absolute path to a json file holding key value pairs of additional parameters ro be appended during client 
registration. This will overwrite any default parameters for a given OIDC provider.

....

A few other environment variables along with their default values are. 

```python
# Flask `SECRET_KEY` config value
FLASK_OIDC_SECRET_KEY: '!-flask-oidc-secret-key'

# Comma separated string of URLs which should be exposed without authentication, else all request will be authenticated.
FLASK_OIDC_WHITELISTED_ENDPOINTS: "status,healthcheck,health"
```

You can also set the config variables specific to [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/en/2.x/config/) using the same key as the environment variables.
```python
# Details about this below in the "Session Management" section.
SQLALCHEMY_DATABASE_URI: 'sqlite:///sessions.db'
```

## Known Issues:
- Need to make sure it still works with the clients_secrets.json file or via env variables for each endpoint of a custom OIDC provider.
- `refresh_token` is not yet working. I am still trying to figure out how to do this using Authlib. 
- You may enter problems when installing cryptography, check its [official document](https://cryptography.io/en/latest/installation/)
