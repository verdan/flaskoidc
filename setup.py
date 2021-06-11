import os

from setuptools import setup, find_packages

requirements = [
    'Authlib==0.15.4',
    'requests==2.25.1',
    'Flask-SQLAlchemy==2.5.1'
]

__version__ = '1.0.0'

setup(
    name='flaskoidc',
    version=__version__,
    description='Flask wrapper with pre-configured OAuth and OIDC support',
    url='https://github.com/verdan/flaskoidc.git',
    author='Verdan Mahmood',
    author_email='verdan.mahmood@gmail.com',
    packages=find_packages(exclude=['tests*']),
    include_package_data=True,
    dependency_links=[],
    install_requires=requirements,
    python_requires=">=3.6",

)
