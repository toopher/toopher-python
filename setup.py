from setuptools import setup

setup(
    name='Toopher',
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
    packages=['toopher',],
    test_suite='tests',
    install_requires=[
        'oauth2',
        ]
)
