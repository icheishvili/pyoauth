from setuptools import setup, find_packages
import sys, os

version = '0.9'

setup(name='pyoauth',
      version=version,
      description="pyOAuth is a Python library for dealing with OAuth",
      long_description="""\
""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='Ilia Cheishvili',
      author_email='',
      url='https://github.com/icheishvili/pyoauth',
      license='BSD',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=[],
      entry_points=""" """,
      )
