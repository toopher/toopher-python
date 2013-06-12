#!/usr/bin/env python
import distribute_setup
distribute_setup.use_setuptools()

from setuptools import setup

setup(
    name='toopher',
    version='1.0.2',
    author='Toopher, Inc.',
    author_email='support@toopher.com',
    url='https://dev.toopher.com',
    description='Wrapper library for the Toopher authentication API',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],
    packages=['toopher'],
    package_data = {'toopher': ['toopher.pem']},
    test_suite='tests',
    install_requires=[
        'oauth2',
        ]
)
