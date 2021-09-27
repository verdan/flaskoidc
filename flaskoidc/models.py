import logging

import time
from authlib.oidc.core.errors import LoginRequiredError
from flask import current_app as app, session
from sqlalchemy import Column, Integer, String, TEXT

LOGGER = logging.getLogger(f"flaskoidc.{__name__}")


class OAuth2Token(app.db.Model):
    id = Column(Integer, primary_key=True)
    user_id = Column(String(320), nullable=False)
    name = Column(String(20), nullable=False)

    access_token = Column(TEXT, nullable=False)
    expires_in = Column(Integer, default=0)
    scope = Column(String(320), default=0)
    token_type = Column(String(20))
    refresh_token = Column(TEXT)
    expires_at = Column(Integer, default=0)

    def to_token(self):
        return dict(
            access_token=self.access_token,
            expires_in=self.expires_in,
            scope=self.scope,
            token_type=self.token_type,
            refresh_token=self.refresh_token,
            expires_at=self.expires_at,
        )

    @property
    def is_active(self):
        return self.expires_at > round(time.time())

    @staticmethod
    def save(**kwargs):
        item = OAuth2Token(**kwargs)
        app.db.session.add(item)
        app.db.session.commit()

    @staticmethod
    def get(**kwargs):
        return OAuth2Token.query.filter_by(**kwargs).first()

    @staticmethod
    def delete(**kwargs):
        OAuth2Token.query.filter_by(**kwargs).delete()
        app.db.session.commit()

    @staticmethod
    def get_active(name, user_id, int_time):
        return OAuth2Token.query.filter(
            OAuth2Token.name == name,
            OAuth2Token.user_id == user_id,
            OAuth2Token.expires_at >= int_time,
        ).first()

    @staticmethod
    def all():
        return OAuth2Token.query.all()

    @staticmethod
    def update_tokens(token, refresh_token=None, access_token=None):
        name = app.config.get("OIDC_PROVIDER")
        if refresh_token:
            item = OAuth2Token.get(name=name, refresh_token=refresh_token)
        elif access_token:
            item = OAuth2Token.get(name=name, access_token=access_token)
        else:
            return

        item.access_token = token["access_token"]
        item.refresh_token = token.get("refresh_token")
        item.expires_at = token["expires_at"]
        app.db.session.commit()


def _update_token(token, refresh_token=None, access_token=None):
    LOGGER.debug(f"Calling _update_token(token={token}...")
    try:
        OAuth2Token.update_tokens(
            token, refresh_token=refresh_token, access_token=access_token
        )
    except Exception:
        LOGGER.exception(
            f"Exception occurred _update_token(token={token}...", exc_info=True
        )


def _fetch_token(name):
    try:
        user_id = session["user"]["__id"]
        LOGGER.debug(f"Calling _fetch_token(name={name},user_id={user_id})...")
        _current_time = round(time.time())
        token = OAuth2Token.get_active(
            name=name, user_id=user_id, int_time=_current_time
        )
        if not token:
            raise LoginRequiredError("_fetch_token: No Token Found or Expired")
        return token.to_token()
    except Exception:
        LOGGER.error("Unexpected Error", exc_info=True)
        raise LoginRequiredError
