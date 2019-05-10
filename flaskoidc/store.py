from flask import session
from collections import UserDict


class SessionCredentialStore(UserDict):
    def __init__(self):
        super().__init__()
        self.session = session

    def __setitem__(self, key, value):
        self.session[key] = value

    def __getitem__(self, key):
        return self.session[key]

    def __delitem__(self, key):
        return self.session.pop(key)

    def __contains__(self, key):
        return key in self.session

    def __repr__(self):
        return 'SessionStore: {}'.format(str(self.__class__))
