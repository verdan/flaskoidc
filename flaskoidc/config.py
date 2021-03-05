import os

OIDC_ATTR_KEY = 'OIDC_'
SQLALCHEMY_ATTR_KEY = 'SQLALCHEMY_'
FLASK_SESSION_ATTR_KEY = 'SESSION_'
EXCEPTIONAL_KEYS = ["OVERWRITE_REDIRECT_URI"]
LIST_KEYS = ["OIDC_SCOPES"]


class OIDCProvider:
    GOOGLE = "GOOGLE"
    KEYCLOAK = "KEYCLOAK"


class BaseConfig(object):
    SECRET_KEY = os.environ.get('FLASK_OIDC_SECRET_KEY', 'base-flask-oidc-secret-key')
    WHITELISTED_ENDPOINTS = os.environ.get('FLASK_OIDC_WHITELISTED_ENDPOINTS',
                                           "status,healthcheck,health")

    # Not being used anywhere
    OIDC_PROVIDER = os.environ.get('FLASK_OIDC_OIDC_PROVIDER', OIDCProvider.KEYCLOAK)

    # Logging Settings
    LOG_FORMAT = '%(asctime)s.%(msecs)03d [%(levelname)s] %(module)s.%(funcName)s:%(lineno)d (%(process)d:' \
                 + '%(threadName)s) - %(message)s'
    LOG_DATE_FORMAT = os.environ.get('FLASK_OIDC_LOG_DATE_FORMAT', '%Y-%m-%dT%H:%M:%S%z')
    LOG_LEVEL = os.environ.get('FLASK_OIDC_LOG_LEVEL', 'INFO')

    # OIDC Settings
    OIDC_CLIENT_SECRETS = os.environ.get('OIDC_CLIENT_SECRETS', 'config/client_secrets.json')
    OIDC_INTROSPECTION_AUTH_METHOD = os.environ.get('INTROSPECTION_AUTH_METHOD',
                                                    'client_secret_post')
    OIDC_ID_TOKEN_COOKIE_SECURE = os.environ.get('OIDC_ID_TOKEN_COOKIE_SECURE', False)

    # Database and Sessions Settings
    SESSION_TYPE = os.environ.get('SESSION_TYPE', 'sqlalchemy')
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS', False)

    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI", 'sqlite:///sessions.db')

    for key, value in dict(os.environ).items():
        if key in LIST_KEYS:
            value = [item.strip() for item in value.split(',')]
        if (
                key.startswith(OIDC_ATTR_KEY) or
                key.startswith(FLASK_SESSION_ATTR_KEY) or
                key.startswith(SQLALCHEMY_ATTR_KEY)
        ):
            locals()[key] = value
        elif key in EXCEPTIONAL_KEYS:
            locals()[key] = value
