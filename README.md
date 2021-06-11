# FlaskOIDC
[![PyPI version](https://badge.fury.io/py/flaskoidc.svg)](https://badge.fury.io/py/flaskoidc)
[![License](http://img.shields.io/:license-Apache%202-blue.svg)](LICENSE)

A wrapper of Flask with pre-configured OIDC support. Ideal for microservices architecture, each request will be authenticated using Flask's `before_request` middleware. Necassary endpoints can be whitelisted using an environment variable `FLASK_OIDC_WHITELISTED_ENDPOINTS`. 



You may enter problems when installing cryptography, check its official document at https://cryptography.io/en/latest/installation/

