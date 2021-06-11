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

    # Logging Settings
    LOG_FORMAT = '%(asctime)s.%(msecs)03d [%(levelname)s] %(module)s.%(funcName)s:%(lineno)d (%(process)d:' \
                 + '%(threadName)s) - %(message)s'
    LOG_DATE_FORMAT = os.environ.get('FLASK_OIDC_LOG_DATE_FORMAT', '%Y-%m-%dT%H:%M:%S%z')
    LOG_LEVEL = os.environ.get('FLASK_OIDC_LOG_LEVEL', 'INFO')

    # FixMe: Change this to a dictionary, and verify if the value is correct
    OIDC_PROVIDER = os.environ.get('FLASK_OIDC_PROVIDER_NAME', 'google')
    OIDC_SCOPES = os.environ.get('FLASK_OIDC_SCOPES', 'openid email profile')
    USER_ID_FIELD = os.environ.get('FLASK_OIDC_USER_ID_FIELD', 'email')
    CLIENT_ID = os.environ.get('FLASK_OIDC_CLIENT_ID',
                                           '434345347485-0ikvlscgvfp9jnfn9cj3f7pk3cq6jebq.apps.googleusercontent.com')
    CLIENT_SECRET = os.environ.get('FLASK_OIDC_CLIENT_SECRET',
                                               '')
    REDIRECT_URI = os.environ.get('FLASK_OIDC_REDIRECT_URI', '/auth')
    CONFIG_URL = os.environ.get('FLASK_OIDC_CONFIG_URL',
                                            'https://accounts.google.com/.well-known/openid-configuration')

    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS', False)
    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI", 'sqlite:///sessions.db')

