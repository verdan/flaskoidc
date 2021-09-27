import json
import logging

import time
from authlib.integrations.flask_client import OAuth
from flask import redirect, Flask, request, session, abort
from flask.helpers import get_env, get_debug_flag, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.exceptions import BadRequest

from flaskoidc.config import BaseConfig, _CONFIGS

LOGGER = logging.getLogger(__name__)


class FlaskOIDC(Flask):
    def _before_request(self):
        from flaskoidc.models import OAuth2Token

        _current_time = round(time.time())
        # Whitelisted Endpoints i.e., health checks and status url
        whitelisted_endpoints = self.config.get("WHITELISTED_ENDPOINTS")
        LOGGER.debug(f"Whitelisted Endpoint: {whitelisted_endpoints}")

        # Add auth endpoints to whitelisted endpoint as well, so not to check for token on that
        whitelisted_endpoints += (
            f",login,logout,{self.config.get('REDIRECT_URI').strip('/')}"
        )

        if request.path.strip("/") in whitelisted_endpoints.split(
            ","
        ) or request.endpoint in whitelisted_endpoints.split(","):
            return

        # If accepting token in the request headers
        token = None
        if "Authorization" in request.headers and request.headers[
            "Authorization"
        ].startswith("Bearer "):
            token = request.headers["Authorization"].split(None, 1)[1].strip()
        if "access_token" in request.form:
            token = request.form["access_token"]
        elif "access_token" in request.args:
            token = request.args["access_token"]

        if token:
            token = json.loads(token)
            if token.get("expires_at") <= _current_time:
                LOGGER.exception("Token coming in request is expired")
                abort(401)
            else:
                LOGGER.debug("Token in request is not expired.")
                try:
                    assert self.auth_client.token
                except Exception as ex:
                    LOGGER.debug(
                        "Token not found in the database, use the one in the request"
                    )
                    # Since this is a request coming from other service,
                    # we will need to assign the token, to use in the code further
                    self.auth_client.token = token
        else:
            try:
                self.auth_client.token
            except Exception as ex:
                LOGGER.exception(
                    "User not logged in, redirecting to auth", exc_info=True
                )
                return redirect(url_for("logout", _external=True))

    def __init__(self, *args, **kwargs):
        super(FlaskOIDC, self).__init__(*args, **kwargs)

        self.db = SQLAlchemy(self)
        _provider = self.config.get("OIDC_PROVIDER").lower()

        if _provider not in _CONFIGS.keys():
            LOGGER.info(
                f"""
            [flaskoidc Notice] I have not verified the OIDC Provider that you have 
            selected i.e., "{_provider}" with this package yet. 
            If you encounter any issue while using this library with "{_provider}",
            please do not hesitate to create an issue on Github. (https://github.com/verdan/flaskoidc)
            """
            )

        with self.app_context():
            from flaskoidc.models import OAuth2Token, _fetch_token, _update_token

            self.db.create_all()

            oauth = OAuth(self, fetch_token=_fetch_token, update_token=_update_token)

            self.auth_client = oauth.register(
                name=_provider,
                server_metadata_url=self.config.get("CONFIG_URL"),
                client_kwargs={
                    "scope": self.config.get("OIDC_SCOPES"),
                },
                **_CONFIGS.get(_provider) if _CONFIGS.get(_provider) else {},
            )

        # Register the before request function that will make sure each
        # request is authenticated before processing
        self.before_request(self._before_request)

        def unauthorized_redirect(err):
            LOGGER.info("Calling the 401 Error Handler. 'unauthorized_redirect'")
            return redirect(url_for("logout", _external=True))

        self.register_error_handler(401, unauthorized_redirect)

        @self.route("/login")
        def login():
            redirect_uri = url_for("auth", _external=True)
            return self.auth_client.authorize_redirect(redirect_uri)

        @self.route(self.config.get("REDIRECT_URI"))
        def auth():
            _db_keys = [
                "access_token",
                "expires_in",
                "scope",
                "token_type",
                "refresh_token",
                "expires_at",
            ]
            try:
                token = self.auth_client.authorize_access_token()
                LOGGER.debug(f"Token Info: {token}")
                user = self.auth_client.parse_id_token(token)
                LOGGER.debug(f"User Info: {user}")
                user_id = user.get(self.config.get("USER_ID_FIELD"))
                if not user_id:
                    raise BadRequest(
                        "Make sure to set the proper 'FLASK_OIDC_USER_ID_FIELD' env variable "
                        "to match with your OIDC Provider."
                        f"'{self.config.get('USER_ID_FIELD')}' is not present in the "
                        f"response from OIDC Provider. Available Keys are: ({', '.join(user.keys())})"
                    )
                # Remove unnecessary keys from the token
                db_token = {_key: token.get(_key) for _key in _db_keys}
                OAuth2Token.save(name=_provider, user_id=user_id, **db_token)
                session["user"] = user
                session["user"]["__id"] = user_id
                return redirect(self.config.get("OVERWRITE_REDIRECT_URI"))
            except Exception as ex:
                LOGGER.exception(ex)
                raise ex

        @self.route("/logout")
        def logout():
            # ToDo: Think of if we should delete the session entity or not
            # if session.get("user"):
            #     OAuth2Token.delete(name=_provider, user_id=session["user"]["__id"])
            session.pop("user", None)
            return redirect(url_for("login"))

    def make_config(self, instance_relative=False):
        """
        Overriding the default `make_config` function in order to support
        Flask OIDC package and all of their settings.
        """
        root_path = self.root_path
        if instance_relative:
            root_path = self.instance_path
        defaults = dict(self.default_config)
        defaults["ENV"] = get_env()
        defaults["DEBUG"] = get_debug_flag()

        _required_fields = ["CLIENT_ID", "CLIENT_SECRET", "CONFIG_URL"]

        # Append all the configurations from the base config class.
        for key, value in BaseConfig.__dict__.items():
            if not key.startswith("__"):
                if key in ["CLIENT_ID", "CLIENT_SECRET"]:
                    key = f"{BaseConfig.OIDC_PROVIDER.upper()}_{key}"

                if key in _required_fields and not value:
                    raise RuntimeError(
                        f"Invalid Configuration: {key} is required and can not be empty."
                    )

                defaults[key] = value
        return self.config_class(root_path, defaults)
