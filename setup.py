from os import path

from setuptools import setup, find_packages

requirements = [
    "Flask>=1.0.2",
    "Authlib==0.15.4",
    "requests==2.25.1",
    "Flask-SQLAlchemy==2.5.1",
]

# read the contents of your README file
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

__version__ = "1.0.4"

setup(
    name="flaskoidc",
    version=__version__,
    description="Flask wrapper with pre-configured OAuth2 and OIDC support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/verdan/flaskoidc.git",
    author="Verdan Mahmood",
    author_email="verdan.mahmood@gmail.com",
    packages=find_packages(exclude=["tests*"]),
    include_package_data=True,
    dependency_links=[],
    install_requires=requirements,
    python_requires=">=3.6",
)
