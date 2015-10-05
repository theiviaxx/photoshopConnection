#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


readme = open('README.rst').read()

requirements = [
    'pbkdf2'
]

test_requirements = [
    'pbkdf2'
]

version = ''
with open('pyps/__init__.py', 'r') as fh:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fh.read(), re.MULTILINE).group(1)

if not version:
    raise RuntimeError('Cannot find version information')

setup(
    name='pyps',
    description='A pure python implentation for communicating to Adobe Photoshop',
    long_description=readme,
    version=version,
    author='Brett Dixon',
    author_email='theiviaxx@gmail.com',
    license='MIT',
    url='https://github.com/theiviaxx/photoshopConnection',
    platforms='any',
    include_package_data=True,
    install_requires=[
        'pbkdf2'
    ],
    packages=[
        'pyps',
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
    zip_safe=False,
    test_suite='tests',
)