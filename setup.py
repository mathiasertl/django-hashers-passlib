# -*- coding: utf-8 -*-
#
# This file is part of django-hashers-passlib
# (https://github.com/mathiasertl/django-hashers-passlib).
#
# django-hashers-passlib is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-hashers-passlib is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# django-hashers-passlib.  If not, see <http://www.gnu.org/licenses/>.

import unittest

try:
    from setuptools import Command
    from setuptools import setup
except ImportError:
    import distribute_setup
    distribute_setup.use_setuptools()
    from setuptools import Command
    from setuptools import setup

from distutils.command.clean import clean as _clean

name = 'django-hashers-passlib'
url = 'https://github.com/mathiasertl/django-hashers-passlib'
version = '0.1'
requires = [
    'passlib>=1.6.2',
    'Django>=1.5',
]


class clean(_clean):
    pass


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
        from test import test_hashers

        loader = unittest.TestLoader()
        if self.algo is None:
            suite = loader.loadTestsFromModule(test_hashers)
        else:
            case = getattr(test_hashers, '%s_test' % self.algo)
            suite = loader.loadTestsFromTestCase(case)
        unittest.TextTestRunner(verbosity=1).run(suite)

setup(
    name=name,
    version=version,
    description='Django hashers using passlib',
    long_description="""TODO.""",
    author='Mathias Ertl',
    author_email='mati@er.tl',
    url=url,
#    download_url='https://python.restauth.net/download/',
    packages=[
        'hashers_passlib',
    ],
    cmdclass={
        'clean': clean,
        'test': test,
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
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.1",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ]
)
