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

from base64 import b64decode
from base64 import b64encode
from binascii import hexlify
from binascii import unhexlify


class Converter(object):
    def from_orig(self, encoded):
        """Convert from the alias to the one we can store in the database"""
        return '%s$%s' % (self.prefix, encoded[len(self.orig_prefix):])

    def to_orig(self, encoded):
        """Convert from the hash in the database back."""
        return '%s%s' % (self.orig_prefix, encoded[len(self.prefix) + 1:])


class LDAPCryptConverter(Converter):
    orig_prefix = '{CRYPT}'


class bcrypt(Converter):
    prefix = 'bcrypt'
    orig_prefix = ''


class bsd_nthash(Converter):
    prefix = 'nthash'
    orig_prefix = '$3$$'


class ldap_md5(Converter):
    def from_orig(self, encoded):
        data = hexlify(b64decode(encoded[5:]))
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return data

    def to_orig(self, encoded):
        data = b64encode(unhexlify(encoded))
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return '{MD5}%s' % data


class ldap_sha1(Converter):
    def from_orig(self, encoded):
        data = hexlify(b64decode(encoded[5:]))
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return 'sha1$$%s' % data

    def to_orig(self, encoded):
        data = b64encode(unhexlify(encoded[6:]))
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return '{SHA}%s' % data


class ldap_hex_md5(Converter):
    def from_orig(self, encoded):
        return encoded[5:]

    def to_orig(self, encoded):
        return '{MD5}%s' % encoded


class ldap_hex_sha1(Converter):
    prefix = 'sha1$'
    orig_prefix = '{SHA}'


class ldap_des_crypt(LDAPCryptConverter):
    prefix = 'des_crypt'


class ldap_bsdi_crypt(LDAPCryptConverter):
    prefix = 'bsdi_crypt'


class ldap_md5_crypt(LDAPCryptConverter):
    prefix = 'md5_crypt'


class ldap_bcrypt(LDAPCryptConverter):
    prefix = 'bcrypt'


class ldap_sha1_crypt(LDAPCryptConverter):
    prefix = 'sha1_crypt'


class ldap_sha256_crypt(LDAPCryptConverter):
    prefix = 'sha256_crypt'


class ldap_sha512_crypt(LDAPCryptConverter):
    prefix = 'sha512_crypt'


class ldap_pbkdf2_sha1(Converter):
    prefix = 'pbkdf2'
    orig_prefix = '{PBKDF2}'


class ldap_pbkdf2_sha256(Converter):
    prefix = 'pbkdf2-sha256'
    orig_prefix = '{PBKDF2-SHA256}'


class ldap_pbkdf2_sha512(Converter):
    prefix = 'pbkdf2-sha512'
    orig_prefix = '{PBKDF2-SHA512}'
