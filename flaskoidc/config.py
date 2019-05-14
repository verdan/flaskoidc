import os


class BaseConfig(object):
    # Application Settings
    SECRET_KEY = os.environ.get('FLASK_OIDC_SECRET_KEY', 'base-dap-config-secret-key')
    WHITELISTED_ENDPOINTS = os.environ.get('FLASK_OIDC_WHITELISTED_ENDPOINTS',
                                           "status,healthcheck,health")

    # Logging Settings
    LOG_FORMAT = '%(asctime)s.%(msecs)03d [%(levelname)s] %(module)s.%(funcName)s:%(lineno)d (%(process)d:' \
                 + '%(threadName)s) - %(message)s'
    LOG_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S%z'
    LOG_LEVEL = 'INFO'

    # OIDC Settings
    OIDC_CLIENT_SECRETS = os.environ.get('FLASK_OIDC_CLIENT_SECRETS', 'config/client_secrets.json')
    OIDC_INTROSPECTION_AUTH_METHOD = 'client_secret_post'
    OIDC_ID_TOKEN_COOKIE_SECURE = False

    # Database and Sessions Settings
    SESSION_TYPE = 'sqlalchemy'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SQLALCHEMY_DATABASE_URI = os.environ.get("FLASK_OIDC_SQLALCHEMY_DATABASE_URI", 'sqlite:///sessions.db')
