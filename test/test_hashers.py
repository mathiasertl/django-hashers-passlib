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

from __future__ import unicode_literals

import os
import sys
import unittest

sys.path.insert(0, 'example')
os.environ['DJANGO_SETTINGS_MODULE'] = 'example.settings'

from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.hashers import load_hashers
from django.contrib.auth.hashers import make_password
from django.test import TestCase

import hashers_passlib

PASSWORDS = [
    'I',
    'DA',
    'RoJ',
    'THxn',
    '1uzPU',
    'oe331f',
    'qBcP47',
    'D4i19w',
    'e8qBbIA',
    'vzCXzq8',
    '7xEmLNYW',
    'HeVCzQ3I',
    'mMIJzMuAo',
    '4gjjrcCfm',
    '3Asa788x6g',
    'AGwKzVP1SC',
    'CWwYP880G4',
    'RK8SMEmv0s',
]

class TestMixin(object):
    @property
    def path(self):
        return '%s.%s' % (self.hasher.__module__, self.hasher.__class__.__name__)

    def test_basic(self):
        with self.settings(PASSWORD_HASHERS=[self.path, ]):
            load_hashers(settings.PASSWORD_HASHERS)

            for password in PASSWORDS:
                encoded = make_password(password)
                self.assertTrue(check_password(password, encoded))


class des_crypt_test(TestCase, TestMixin):
    hasher = hashers_passlib.des_crypt()


class bsdi_crypt_test(TestCase, TestMixin):
    hasher = hashers_passlib.bsdi_crypt()


class bigcrypt_test(TestCase, TestMixin):
    hasher = hashers_passlib.bsdi_crypt()


class crypt16_test(TestCase, TestMixin):
    hasher = hashers_passlib.crypt16()


class md5_crypt_test(TestCase, TestMixin):
    hasher = hashers_passlib.md5_crypt()
