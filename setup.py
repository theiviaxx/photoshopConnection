#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='pyps',
    description='A pure python implentation for communicating to Adobe Photoshop',
    long_description='A pure python implentation for communicating to and subscribing to events from Adobe Photoshop',
    version='0.5.1',
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