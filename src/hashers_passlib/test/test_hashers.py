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

"""Test for all hasher classes."""

# pylint: disable=missing-class-docstring,invalid-name

from collections import OrderedDict

import passlib
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.test import TestCase

import hashers_passlib
from hashers_passlib import converters

PASSWORDS = [
    "I",
    "DA",
    "RoJ",
    "THxn",
    "1uzPU",
    "oe331f",
    "qBcP47",
    # 'D4i19w',
    # 'e8qBbIA',
    # 'vzCXzq8',
    # '7xEmLNYW',
    # 'HeVCzQ3I',
    # 'mMIJzMuAo',
    # '4gjjrcCfm',
    # '3Asa788x6g',
    # 'AGwKzVP1SC',
    # 'CWwYP880G4',
    # 'RK8SMEmv0s',
]


class TestMixin:
    @property
    def path(self):
        """Shortcut for getting the  full classpath to the hasher."""
        return f"{self.hasher.__module__}.{self.hasher.__class__.__name__}"

    def assertSummary(self, encoded):
        """Assert that the summary is as expected."""
        summary = self.hasher.safe_summary(encoded)
        self.assertTrue(isinstance(summary, OrderedDict))
        self.assertTrue(len(summary) >= 1)

    def test_check(self):
        """Test creating passwords and checking them again using our hashes."""
        with self.settings(PASSWORD_HASHERS=[self.path]):
            for password in PASSWORDS:
                encoded = make_password(password)
                self.assertTrue(check_password(password, encoded))

                self.assertSummary(encoded)

                # test to_orig, done here, to save a few hash-generations
                encoded_orig = self.hasher.to_orig(encoded)
                self.assertTrue(self.hasher.hasher.verify(password, encoded_orig))

                back = self.hasher.from_orig(encoded_orig)
                self.assertEqual(encoded, back)

    def test_user_model(self):
        """Test the django user password."""
        password = "foobar-random"
        user = User.objects.create(username="foobar")

        with self.settings(PASSWORD_HASHERS=[self.path]):
            user.set_password(password)
            user.save()

            self.assertTrue(user.check_password(password))

        # this is False because no hasher recognizes the format
        with self.settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.PBKDF2PasswordHasher"]):
            self.assertFalse(user.check_password(password))

        with self.settings(PASSWORD_HASHERS=[self.path]):
            self.assertTrue(user.check_password(password))


class TestConverterMixin:
    def setUp(self):  # pylint: disable=missing-function-docstring
        self.alt_hasher = getattr(passlib.hash, self.converter.__class__.__name__)

    def test_base(self):
        """Basic test for converters."""
        with self.settings(PASSWORD_HASHERS=[self.hasher]):
            for password in PASSWORDS:
                orig = self.alt_hasher.encrypt(password)
                conv = self.converter.from_orig(orig)

                # see if we get a working hash:
                self.assertTrue(check_password(password, conv))

                # convert back and test with passlib:
                back = self.converter.to_orig(conv)
                self.assertEqual(orig, back)


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


class sha1_crypt_test(TestCase, TestMixin):
    hasher = hashers_passlib.sha1_crypt()


class sun_md5_crypt_test(TestCase, TestMixin):
    hasher = hashers_passlib.sun_md5_crypt()


class sha256_crypt_test(TestCase, TestMixin):
    hasher = hashers_passlib.sha256_crypt()


class sha512_crypt_test(TestCase, TestMixin):
    hasher = hashers_passlib.sha512_crypt()


class apr_md5_crypt_test(TestCase, TestMixin):
    hasher = hashers_passlib.apr_md5_crypt()


class bcrypt_sha256_test(TestCase, TestMixin):
    hasher = hashers_passlib.bcrypt_sha256()


class phpass_test(TestCase, TestMixin):
    hasher = hashers_passlib.phpass()


class pbkdf2_sha1_test(TestCase, TestMixin):
    hasher = hashers_passlib.pbkdf2_sha1()


class pbkdf2_sha256_test(TestCase, TestMixin):
    hasher = hashers_passlib.pbkdf2_sha256()

    def test_settings(self):
        """Test passing additional kwargs to the hasher."""
        encoded = self.hasher.encode("foobar", rounds=32)
        self.assertEqual(self.hasher.safe_summary(encoded)["iterations"], 32)

        encoded = self.hasher.encode("foobar", rounds=64)
        self.assertEqual(self.hasher.safe_summary(encoded)["iterations"], 64)

        kwargs = {"pbkdf2_sha256": {"rounds": 64}}

        with self.settings(PASSWORD_HASHERS=[self.path], PASSLIB_KEYWORDS=kwargs):
            encoded = self.hasher.encode("foobar")
        self.assertEqual(self.hasher.safe_summary(encoded)["iterations"], 64)


class pbkdf2_sha512_test(TestCase, TestMixin):
    hasher = hashers_passlib.pbkdf2_sha512()


class cta_pbkdf2_sha1_test(TestCase, TestMixin):
    hasher = hashers_passlib.cta_pbkdf2_sha1()


class dlitz_pbkdf2_sha1_test(TestCase, TestMixin):
    hasher = hashers_passlib.dlitz_pbkdf2_sha1()


class scram_test(TestCase, TestMixin):
    hasher = hashers_passlib.scram()


class ldap_salted_md5_test(TestCase, TestMixin):
    hasher = hashers_passlib.ldap_salted_md5()


class ldap_salted_sha1_test(TestCase, TestMixin):
    hasher = hashers_passlib.ldap_salted_sha1()


class atlassian_pbkdf2_sha1_test(TestCase, TestMixin):
    hasher = hashers_passlib.atlassian_pbkdf2_sha1()


class fshp_test(TestCase, TestMixin):
    hasher = hashers_passlib.fshp()


class mssql2000_test(TestCase, TestMixin):
    hasher = hashers_passlib.mssql2000()


class mssql2005_test(TestCase, TestMixin):
    hasher = hashers_passlib.mssql2005()


class mysql323_test(TestCase, TestMixin):
    hasher = hashers_passlib.mysql323()


class mysql41_test(TestCase, TestMixin):
    hasher = hashers_passlib.mysql41()


class oracle11_test(TestCase, TestMixin):
    hasher = hashers_passlib.oracle11()


class lmhash_test(TestCase, TestMixin):
    hasher = hashers_passlib.lmhash()


class nthash_test(TestCase, TestMixin):
    hasher = hashers_passlib.nthash()


class cisco_pix_test(TestCase, TestMixin):
    hasher = hashers_passlib.cisco_pix()


class cisco_type7_test(TestCase, TestMixin):
    hasher = hashers_passlib.cisco_type7()


class grub_pbkdf2_sha512_test(TestCase, TestMixin):
    hasher = hashers_passlib.grub_pbkdf2_sha512()


class hex_md4_test(TestCase, TestMixin):
    hasher = hashers_passlib.hex_md4()


class hex_sha256_test(TestCase, TestMixin):
    hasher = hashers_passlib.hex_sha256()


class hex_sha512_test(TestCase, TestMixin):
    hasher = hashers_passlib.hex_sha512()


class argon2d_test(TestCase, TestMixin):
    hasher = hashers_passlib.argon2d()


class argon2i_test(TestCase, TestMixin):
    hasher = hashers_passlib.argon2i()


class argon2id_test(TestCase, TestMixin):
    hasher = hashers_passlib.argon2id()


class scrypt_test(TestCase, TestMixin):
    hasher = hashers_passlib.scrypt()


class bcrypt_test(TestConverterMixin, TestCase):
    hasher = "django.contrib.auth.hashers.BCryptPasswordHasher"
    converter = converters.bcrypt()


class bsd_nthash_test(TestConverterMixin, TestCase):
    hasher = "hashers_passlib.nthash"
    converter = converters.bsd_nthash()


class ldap_md5_test(TestConverterMixin, TestCase):
    hasher = "django.contrib.auth.hashers.UnsaltedMD5PasswordHasher"
    converter = converters.ldap_md5()


class ldap_sha1_test(TestConverterMixin, TestCase):
    hasher = "django.contrib.auth.hashers.UnsaltedSHA1PasswordHasher"
    converter = converters.ldap_sha1()


class ldap_hex_md5_test(TestConverterMixin, TestCase):
    hasher = "django.contrib.auth.hashers.UnsaltedMD5PasswordHasher"
    converter = converters.ldap_hex_md5()


class ldap_hex_sha1_test(TestConverterMixin, TestCase):
    hasher = "django.contrib.auth.hashers.UnsaltedSHA1PasswordHasher"
    converter = converters.ldap_hex_sha1()


class ldap_des_crypt_test(TestConverterMixin, TestCase):
    hasher = "hashers_passlib.des_crypt"
    converter = converters.ldap_des_crypt()


class ldap_bsdi_crypt_test(TestConverterMixin, TestCase):
    hasher = "hashers_passlib.bsdi_crypt"
    converter = converters.ldap_bsdi_crypt()


class ldap_md5_crypt_test(TestConverterMixin, TestCase):
    hasher = "hashers_passlib.md5_crypt"
    converter = converters.ldap_md5_crypt()


class ldap_bcrypt_test(TestConverterMixin, TestCase):
    hasher = "django.contrib.auth.hashers.BCryptPasswordHasher"
    converter = converters.ldap_bcrypt()


class ldap_sha1_crypt_test(TestConverterMixin, TestCase):
    hasher = "hashers_passlib.sha1_crypt"
    converter = converters.ldap_sha1_crypt()


class ldap_sha256_crypt_test(TestConverterMixin, TestCase):
    hasher = "hashers_passlib.sha256_crypt"
    converter = converters.ldap_sha256_crypt()


class ldap_sha512_crypt_test(TestConverterMixin, TestCase):
    hasher = "hashers_passlib.sha512_crypt"
    converter = converters.ldap_sha512_crypt()


class ldap_pbkdf2_sha1_test(TestConverterMixin, TestCase):
    hasher = "hashers_passlib.pbkdf2_sha1"
    converter = converters.ldap_pbkdf2_sha1()


class ldap_pbkdf2_sha256_test(TestConverterMixin, TestCase):
    hasher = "hashers_passlib.pbkdf2_sha256"
    converter = converters.ldap_pbkdf2_sha256()


class ldap_pbkdf2_sha512_test(TestConverterMixin, TestCase):
    hasher = "hashers_passlib.pbkdf2_sha512"
    converter = converters.ldap_pbkdf2_sha512()
