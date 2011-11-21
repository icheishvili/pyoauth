from setuptools import setup, find_packages
import sys, os

version = '0.9'

setup(name='ioauth',
      version=version,
      description="iOAuth is a Python library for dealing with OAuth",
      long_description="""\
""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='Ilia Cheishvili',
      author_email='',
      url='https://github.com/icheishvili/ioauth',
      license='BSD',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=[],
      entry_points=""" """,
      )
