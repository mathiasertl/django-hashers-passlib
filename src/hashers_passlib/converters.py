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

"""Collection of converters to convert hashes into known hashable strings."""

# pylint: disable=invalid-name  # class names usually match the hash algorithm name.


from base64 import b64decode, b64encode
from binascii import hexlify, unhexlify


class Converter:
    """Base class for all converters."""

    prefix: str
    orig_prefix: str

    def from_orig(self, encoded):
        """Convert from the alias to the one we can store in the database"""
        encoded = encoded[len(self.orig_prefix) :]
        return f"{self.prefix}${encoded}"

    def to_orig(self, encoded):
        """Convert from the hash in the database back."""
        encoded = encoded[len(self.prefix) + 1 :]
        return f"{self.orig_prefix}{encoded}"


class LDAPCryptConverter(Converter):
    """Base class for all ``{CRYPT}`` converter."""

    orig_prefix = "{CRYPT}"


class bcrypt(Converter):
    """Convert a plain :py:class:`passlib:passlib.hash.bcrypt` to a a BCrypt hash usable by Django."""

    prefix = "bcrypt"
    orig_prefix = ""


class bsd_nthash(Converter):
    """Convert a :py:class:`passlib:passlib.hash.bsd_nthash` to :py:class:`hashers_passlib.nthash`."""

    prefix = "nthash"
    orig_prefix = "$3$$"


class ldap_md5(Converter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_md5` to a plain MD5 hash."""

    def from_orig(self, encoded):
        data = hexlify(b64decode(encoded[5:]))
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return data

    def to_orig(self, encoded):
        data = b64encode(unhexlify(encoded))
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return f"{{MD5}}{data}"


class ldap_sha1(Converter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_sha1` to a plain SHA1 hash."""

    def from_orig(self, encoded):
        data = hexlify(b64decode(encoded[5:]))
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return f"sha1$${data}"

    def to_orig(self, encoded):
        data = b64encode(unhexlify(encoded[6:]))
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return f"{{SHA}}{data}"


class ldap_hex_md5(Converter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_hex_md5` to a plain MD5 hash."""

    def from_orig(self, encoded):
        return encoded[5:]

    def to_orig(self, encoded):
        return f"{{MD5}}{encoded}"


class ldap_hex_sha1(Converter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_hex_sha1` to a plain SHA1 hash."""

    prefix = "sha1$"
    orig_prefix = "{SHA}"


class ldap_des_crypt(LDAPCryptConverter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_des_crypt` to a normal crypt hash."""

    prefix = "des_crypt"


class ldap_bsdi_crypt(LDAPCryptConverter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_bsdi_crypt` to a normal crypt hash."""

    prefix = "bsdi_crypt"


class ldap_md5_crypt(LDAPCryptConverter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_md5_crypt` to a normal crypt hash."""

    prefix = "md5_crypt"


class ldap_bcrypt(LDAPCryptConverter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_md5_crypt` to a normal crypt hash."""

    prefix = "bcrypt"


class ldap_sha1_crypt(LDAPCryptConverter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_sha1_crypt` to a normal crypt hash."""

    prefix = "sha1_crypt"


class ldap_sha256_crypt(LDAPCryptConverter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_sha256_crypt` to a normal crypt hash."""

    prefix = "sha256_crypt"


class ldap_sha512_crypt(LDAPCryptConverter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_sha512_crypt` to a normal crypt hash."""

    prefix = "sha512_crypt"


class ldap_pbkdf2_sha1(Converter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_pbkdf2_sha1` to a normal PBKDF2 hash."""

    prefix = "pbkdf2"
    orig_prefix = "{PBKDF2}"


class ldap_pbkdf2_sha256(Converter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_pbkdf2_sha256` to a normal PBKDF2 hash."""

    prefix = "pbkdf2-sha256"
    orig_prefix = "{PBKDF2-SHA256}"


class ldap_pbkdf2_sha512(Converter):
    """Convert a :py:class:`passlib:passlib.hash.ldap_pbkdf2_sha512` to a normal PBKDF2 hash."""

    prefix = "pbkdf2-sha512"
    orig_prefix = "{PBKDF2-SHA512}"
