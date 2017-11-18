# -*- coding: utf-8 -*-
#
# This file is part of django-hashers-passlib (https://github.com/mathiasertl/django-hashers-passlib).
#
# django-hashers-passlib is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# django-hashers-passlib is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License along with django-hashers-passlib. If not,
# see <http://www.gnu.org/licenses/>.

import os
import subprocess
import sys

from setuptools import Command
from setuptools import setup

name = 'django-hashers-passlib'
url = 'https://github.com/mathiasertl/django-hashers-passlib'
LATEST_RELEASE = '0.4'
requires = [
    'passlib>=1.6.5',
    'Django>=1.8',
]


class version(Command):
    description = "Print version and exit."
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        print(LATEST_RELEASE)


class style(Command):
    descriptions = 'Run syntax and style checks.'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        flake = ['flake8', 'setup.py', 'hashers_passlib/']
        print(' '.join(flake))
        code = subprocess.call(flake)
        if code != 0:
            sys.exit(code)

        isort = ['isort', '--check-only', '--diff', '-rc', 'setup.py', 'hashers_passlib/']
        print(' '.join(isort))
        code = subprocess.call(isort)
        if code != 0:
            sys.exit(code)


class test(Command):
    description = 'Run test suite.'
    user_options = [
        (str('algo='), None, 'Only test the specified algorithm'),
    ]

    def initialize_options(self):
        self.algo = None

    def finalize_options(self):
        pass

    def run(self):
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'test.django_settings')
        #sys.path.insert(0, '.')
        import django
        django.setup()

        from django.core.management import call_command
        suite = 'test'
        if self.algo is not None:
            suite = 'test.test_hashers.%s_test' % self.algo

        call_command('test', suite)


setup(
    name=name,
    version=LATEST_RELEASE,
    description='Django hashers using passlib',
    long_description="""This library provides password hashers for the hash schemes provided by passlib for
Djangos password hashing framework. Unlike passlibs ``passlib.apps.django``, it does not replace Djangos
password hashing framework but adds additional hashers to its built in framework.

Please see https://github.com/mathiasertl/django-hashers-passlib for more information and documentation.""",
    author='Mathias Ertl',
    author_email='mati@er.tl',
    url=url,
    packages=[
        'hashers_passlib',
    ],
    cmdclass={
        'style': style,
        'test': test,
        'version': version,
    },
    license="GNU General Public License (GPL) v3",
    install_requires=requires,
    classifiers=[
        "Development Status :: 6 - Mature",
        "Environment :: Other Environment",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ]
)
