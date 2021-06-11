import logging

import time
from authlib.oidc.core.errors import LoginRequiredError
from flask import current_app as app, redirect, url_for, session
from sqlalchemy import Column, Integer, String

LOGGER = logging.getLogger(__name__)


class OAuth2Token(app.db.Model):
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    name = Column(String(20), nullable=False)

    access_token = Column(String(255), nullable=False)
    expires_in = Column(Integer, default=0)
    scope = Column(String, default=0)
    token_type = Column(String(20))
    refresh_token = Column(String(255))
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
    def get_active(name, user_id, int_time):
        return OAuth2Token.query.filter(OAuth2Token.name == name,
                                        OAuth2Token.user_id == user_id,
                                        OAuth2Token.expires_at >= int_time
                                        ).first()

    @staticmethod
    def all():
        return OAuth2Token.query.all()


def _update_token(sender, name, token, refresh_token=None, access_token=None):
    LOGGER.exception("NOT AN EXCEPTION. JUST VERBOSE. on_token_update")
    LOGGER.debug(f"Name: {name}, RefreshToken: {refresh_token}, AccessToken: {access_token}")
    LOGGER.debug(f"Sender: {sender}")
    if refresh_token:
        item = OAuth2Token.where(name=name, refresh_token=refresh_token).first()
    elif access_token:
        item = OAuth2Token.where(name=name, access_token=access_token).first()
    else:
        return

    item.update(
        access_token=token['access_token'],
        refresh_token=token.get('refresh_token'),
        expires_at=token['expires_at']
    )


def _fetch_token(name):
    try:
        _current_time = round(time.time())
        LOGGER.debug(f"Calling _fetch_token(name={name})")
        token = OAuth2Token.get_active(name=name,
                                       user_id=session["user"]["__id"],
                                       int_time=_current_time)
        if not token:
            raise Exception("_fetch_token: No Token Found or Expired")
        return token.to_token()
    except Exception as ex:
        LOGGER.error(ex)
        raise LoginRequiredError
