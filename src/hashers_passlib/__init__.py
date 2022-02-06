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

"""Collection of hashers based on passlib hashers."""

# pylint: disable=invalid-name  # class names follow their passlib counterparts

from collections import OrderedDict

from django.conf import settings
from django.contrib.auth.hashers import BasePasswordHasher, mask_hash
from django.utils.translation import gettext_noop as _

_SETTINGS_MAPPING = (
    (_("rounds"), "iterations", False),
    (_("salt"), "salt", 2),
    (_("checksum"), "hash", 6),
)

VERSION_STR = "1.0.0"
VERSION = tuple(VERSION_STR.split("."))


class PasslibHasher(BasePasswordHasher):
    """Base class for all passlib-based hashers."""

    library = "passlib.hash"
    handler = None
    using = {}
    _hasher = None
    _algorithm = None

    def salt(self):
        """Just return None, passlib handles salt-generation."""
        return None

    @property
    def algorithm(self):
        """Get name of the algorithm as used in the Django database."""
        if self._algorithm is None:
            self._algorithm = self.__class__.__name__
        return self._algorithm

    def get_handler(self):
        """Get the function name used by the hash algorithm.

        This defaults to the name of the algorithm, but sometimes we need to override it.
        """
        if self.handler is None:
            return self.algorithm
        return self.handler

    @property
    def hasher(self):
        """Property to get the passlib hasher class."""
        if self._hasher is None:
            self._hasher = getattr(self._load_library(), self.get_handler())
        return self._hasher

    def verify(self, password, encoded):
        return self.hasher.verify(password, self.to_orig(encoded))

    def encode(self, password, salt=None, **kwargs):
        using = dict(self.using)

        if salt is not None:
            using["salt"] = salt

        using.update(getattr(settings, "PASSLIB_KEYWORDS", {}).get(self.hasher.name, {}))
        using.update(kwargs)
        encoded = self.hasher.using(**using).encrypt(password)

        return self.from_orig(encoded)

    def decode(self, encoded):
        algorithm, encoded = encoded.split("$", 1)
        return {"algorithm": algorithm, "hash": encoded}

    def from_orig(self, encrypted):
        """Convert haash to format as stored in the Django database."""
        return f"{self.algorithm}${encrypted}"

    def to_orig(self, encoded):
        """Convert hash to format produced by passlib."""
        return encoded.split("$", 1)[1]

    def safe_summary(self, encoded):
        algorithm, _hash = encoded.split("$", 1)
        assert algorithm == self.algorithm

        data = [
            (_("algorithm"), algorithm),
        ]
        to_append = []

        parsed = self.hasher.parsehash(self.to_orig(encoded))

        # pop known fields that should be at the end first:
        for name, mapping, mask in _SETTINGS_MAPPING:
            value = parsed.pop(name, None)

            if value is not None:
                if mask is not False:
                    try:
                        # value is an int in some rare cases:
                        value = mask_hash(str(value), show=mask)
                    except UnicodeDecodeError:
                        # Thrown if non-ascii bytes are in the hash
                        # pylint: disable=consider-using-f-string
                        value = "%s%s" % ("?" * mask, "*" * (len(value) - mask))

                to_append.append((mapping, value))

        # parse any left-over fields:
        for key, value in parsed.items():
            data.append((_(key), value))

        return OrderedDict(data + to_append)


class PasslibCryptSchemeHasher(PasslibHasher):
    """Base class for hash algorithms where the passlib version of the hash just prepends a ``"$"``."""

    def from_orig(self, encrypted):
        return encrypted.lstrip("$")

    def to_orig(self, encoded):
        return f"${encoded}"


########################
# Archaic Unix Schemes #
########################
class des_crypt(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.des_crypt`."""


class bsdi_crypt(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.bsdi_crypt`."""


class bigcrypt(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.bigcrypt`."""


class crypt16(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.crypt16`."""


#########################
# Standard Unix Schemes #
#########################
class md5_crypt(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.md5_crypt`."""


class sha1_crypt(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.sha1_crypt`."""


class sun_md5_crypt(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.sun_md5_crypt`."""


class sha256_crypt(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.sha256_crypt`."""


class sha512_crypt(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.sha512_crypt`."""


###############################
# Other Modular Crypt Schemes #
###############################
class apr_md5_crypt(PasslibCryptSchemeHasher):
    """Hasher for :py:class:`passlib:passlib.hash.apr_md5_crypt`."""

    handler = "apr_md5_crypt"
    algorithm = "apr1"


class bcrypt_sha256(PasslibCryptSchemeHasher):
    """Hasher for :py:class:`passlib:passlib.hash.bcrypt_sha256`."""

    handler = "bcrypt_sha256"
    algorithm = "bcrypt-sha256"


class phpass(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.phpass`."""


class pbkdf2_sha1(PasslibCryptSchemeHasher):
    """Hasher for :py:class:`passlib:passlib.hash.pbkdf2_sha1`."""

    handler = "pbkdf2_sha1"
    algorithm = "pbkdf2"


class pbkdf2_sha256(PasslibCryptSchemeHasher):
    """Hasher for :py:class:`passlib:passlib.hash.pbkdf2_sha256`."""

    handler = "pbkdf2_sha256"
    algorithm = "pbkdf2-sha256"


class pbkdf2_sha512(PasslibCryptSchemeHasher):
    """Hasher for :py:class:`passlib:passlib.hash.pbkdf2_sha512`."""

    handler = "pbkdf2_sha512"
    algorithm = "pbkdf2-sha512"


class cta_pbkdf2_sha1(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.cta_pbkdf2_sha1`."""


class dlitz_pbkdf2_sha1(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.dlitz_pbkdf2_sha1`."""


class scram(PasslibCryptSchemeHasher):
    """Hasher for :py:class:`passlib:passlib.hash.scram`."""


# bsd_nthash is provided by a converter

#########################
# Standard LDAP schemes #
#########################
# ldap_md5 is provided by a converter
# ldap_sha1 is provided by a converter
class ldap_salted_md5(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.ldap_salted_md5`."""


class ldap_salted_sha1(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.ldap_salted_sha1`."""


# ldap_{crypt} provided by a converter
# ldap_plaintext makes no sense to support

#############################
# Non-Standard LDAP Schemes #
#############################
# ldap_hex_md5 is provided by a converter
# ldap_hex_sha1 is provided by a converter
# ldap_pbkdf2_{digest} is provided by a converter


class atlassian_pbkdf2_sha1(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.atlassian_pbkdf2_sha1`."""


class fshp(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.fshp"""


# roundup_plaintext makes no sense to support


#######################
# SQL Database Hashes #
#######################
class mssql2000(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.mssql2000`."""


class mssql2005(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.mssql2005`."""


class mysql323(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.mysql323`."""


class mysql41(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.mysql41`."""


# postgres_md5 is incompatible (requires username for hash)
# oracle10 is incompatible (requires username for hash)


class oracle11(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.oracle11`."""


#####################
# MS Windows Hashes #
#####################
class lmhash(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.lmhash`."""


class nthash(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.nthash`."""


# msdcc is incompatible (requires username for hash)
# msdcc2 is incompatible (requires username for hash)


################
# Other hashes #
################
class cisco_pix(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.cisco_pix`."""


class cisco_type7(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.cisco_type7`."""


# django_{digest} not supported, for obvious reasons


class grub_pbkdf2_sha512(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.grub_pbkdf2_sha512`."""


class hex_md4(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.hex_md4`."""


# hex_md5 is already supported by Django
# hex_sha1 is already supported by Django


class hex_sha256(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.hex_sha256`."""


class hex_sha512(PasslibHasher):
    """Hasher for :py:class:`passlib:passlib.hash.hex_sha512`."""


##########################
# Hashers added in 1.7.1 #
##########################


class argon2i(PasslibCryptSchemeHasher):
    """

    This hasher requires that you install the ``argon-cffi`` package.

    .. seealso:: https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html

    .. versionadded:: 0.4
    """

    handler = "argon2"
    algorithm = "argon2i"
    using = {"type": "I"}


class scrypt(PasslibCryptSchemeHasher):
    """

    This hasher requires that you install the ``scrypt`` package.

    .. seealso:: https://passlib.readthedocs.io/en/stable/lib/passlib.hash.scrypt.html

    .. versionadded:: 1.0.0
    """


##########################
# Hashers added in 1.7.2 #
##########################
class argon2d(argon2i):
    """Same as :py:class:`~hashers_passlib.argon2i`, but using the ``D`` type.

    This hasher requires that you install the ``argon-cffi`` package.

    .. seealso:: https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html

    .. versionadded:: 1.0.0
    """

    using = {"type": "D"}
    algorithm = "argon2d"


class argon2id(argon2i):
    """Same as :py:class:`~hashers_passlib.argon2i`, but using the ``ID`` type.

    This hasher requires that you install the ``argon-cffi`` package.

    .. seealso:: https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html

    .. versionadded:: 1.0.0
    """

    using = {"type": "ID"}
    algorithm = "argon2id"
