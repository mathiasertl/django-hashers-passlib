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

from base64 import b64encode
from base64 import b64decode
from binascii import unhexlify
from binascii import hexlify


class Converter(object):
    def from_orig(self, encoded):
        """Convert from the alias to the one we can store in the database"""
        raise NotImplementedError

    def to_orig(self, encoded):
        """Convert from the hash in the database back."""
        raise NotImplementedError


class bsd_nthash(Converter):
    def from_orig(self, encoded):
        return encoded[4:]

    def to_orig(self, encoded):
        return '$3$$%s' % encoded


class ldap_md5(Converter):
    def from_orig(self, encoded):
        return hexlify(b64decode(encoded[5:]))

    def to_orig(self, encoded):
        return '{MD5}%s' % b64encode(unhexlify(encoded))


class ldap_sha1(Converter):
    def from_orig(self, encoded):
        return 'sha1$$%s' % hexlify(b64decode(encoded[5:]))

    def to_orig(self, encoded):
        return '{SHA}%s' % b64encode(unhexlify(encoded[6:]))


class ldap_hex_md5(Converter):
    def from_orig(self, encoded):
        return encoded[5:]

    def to_orig(self, encoded):
        return '{MD5}%s' % encoded


class ldap_hex_sha1(Converter):
    def from_orig(self, encoded):
        return 'sha1$$%s' % encoded[5:]

    def to_orig(self, encoded):
        return '{SHA}%s' % encoded[6:]
