# pylint: disable-all
# type: ignore
from setuptools import setup

exec(open("pytiled_parser/version.py").read())
setup(version=__version__)
