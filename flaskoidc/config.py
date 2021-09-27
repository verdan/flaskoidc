import os


class OIDC_PROVIDERS:
    GOOGLE = "google"
    OKTA = "okta"
    KEYCLOAK = "keycloak"
    CUSTOM = "custom"


# All the custom configurations required for an OIDC provider to work with Authlib
# will go in here. We'll pass these while registering a client.
_CONFIGS = {
    OIDC_PROVIDERS.GOOGLE: {
        "authorize_params": {"access_type": "offline", "prompt": "consent"}
    },
    OIDC_PROVIDERS.OKTA: {},
    OIDC_PROVIDERS.KEYCLOAK: {},
    OIDC_PROVIDERS.CUSTOM: {},
}


class BaseConfig(object):
    SECRET_KEY = os.environ.get("FLASK_OIDC_SECRET_KEY", "!-flask-oidc-secret-key")
    WHITELISTED_ENDPOINTS = os.environ.get(
        "FLASK_OIDC_WHITELISTED_ENDPOINTS", "status,healthcheck,health"
    )

    OIDC_PROVIDER = os.environ.get("FLASK_OIDC_PROVIDER_NAME", "google")
    OIDC_SCOPES = os.environ.get("FLASK_OIDC_SCOPES", "openid email profile")
    USER_ID_FIELD = os.environ.get("FLASK_OIDC_USER_ID_FIELD", "email")
    CLIENT_ID = os.environ.get("FLASK_OIDC_CLIENT_ID", "")
    CLIENT_SECRET = os.environ.get("FLASK_OIDC_CLIENT_SECRET", "")
    REDIRECT_URI = os.environ.get("FLASK_OIDC_REDIRECT_URI", "/auth")
    OVERWRITE_REDIRECT_URI = os.environ.get("FLASK_OIDC_OVERWRITE_REDIRECT_URI", "/")
    CONFIG_URL = os.environ.get("FLASK_OIDC_CONFIG_URL", "")

    OIDC_PROVIDER_PARAMETERS_FILE = os.environ.get(
        "FLASK_OIDC_PROVIDER_ADDITIONAL_PARAMETERS_FILE_PATH", None
    )
    if OIDC_PROVIDER_PARAMETERS_FILE:
        import json

        with open(OIDC_PROVIDER_PARAMETERS_FILE) as parameters_file:
            parameters = json.load(parameters_file)
            _CONFIGS[OIDC_PROVIDER] = parameters

    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get(
        "SQLALCHEMY_TRACK_MODIFICATIONS", False
    )
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "SQLALCHEMY_DATABASE_URI", "sqlite:///sessions.db"
    )
