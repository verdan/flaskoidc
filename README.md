# FlaskOIDC
A wrapper of Flask with pre-configured OIDC support. 

## Usage:

After simply installing the flaskoidc you can simply use it like below:

```python
from flaskoidc import FlaskOIDC
app = FlaskOIDC(__name__)
``` 

## Configurations:

Please make sure to extend your configurations from `DAPConfig`, as it's really IMPORTANT.

```python
from flaskoidc import FlaskOIDC
from flaskoidc.config import BaseConfig

# Custom configuration class, a subclass of DAPConfig
CustomConfig(BaseConfig):
    DEBUG = True

app = FlaskOIDC(__name__)
app.config.from_object(CustomConfig)

```

Following environment variables along with their default values are available and must be set based on the settings. 

```python
# Flask `SECRET_KEY` config value
FLASK_OIDC_SECRET_KEY: 'base-flask-oidc-secret-key'

# List of URLs which should be exposed without authentication, else all request will be authenticated.
FLASK_OIDC_WHITELISTED_ENDPOINTS: ['status', 'healthcheck', 'health']

# Path of your configuration file. (default value assumes you have a `config/client_secrets.json` available.
FLASK_OIDC_CLIENT_SECRETS: 'config/client_secrets.json'

# Details about this below in the "Session Management" section.
FLASK_OIDC_SQLALCHEMY_DATABASE_URI: 'sqlite:///sessions.db'

```

## Session Management
This extension uses SQLAlchemy to hold the sessions of the users. Flask OIDC saves the sessions in memory by default 
which is very vulnerable. This adds the support of custom session store. 
By default the path of database is `sqlite://` and can be configured using the environment variable `FLASK_OIDC_SQLALCHEMY_DATABASE_URI`




