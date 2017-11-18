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

from __future__ import unicode_literals

from collections import OrderedDict

from django.conf import settings
from django.contrib.auth.hashers import BasePasswordHasher
from django.contrib.auth.hashers import mask_hash
from django.utils.translation import ugettext_noop as _

_SETTINGS_MAPPING = (
    (_('rounds'), 'iterations', False),
    (_('salt'), 'salt', 2),
    (_('checksum'), 'hash', 6),
)

VERSION = (0, 4, )


def get_version():
    return '.'.join([str(t) for t in VERSION])


class PasslibHasher(BasePasswordHasher):
    """Base class for all passlib-based hashers."""

    library = "passlib.hash"
    handler = None
    _hasher = None
    _algorithm = None

    def salt(self):
        """Just return None, passlib handles salt-generation."""
        return None

    @property
    def algorithm(self):
        if self._algorithm is None:
            self._algorithm = self.__class__.__name__
        return self._algorithm

    def get_handler(self):
        if self.handler is None:
            return self.algorithm
        return self.handler

    @property
    def hasher(self):
        if self._hasher is None:
            self._hasher = getattr(self._load_library(), self.get_handler())
        return self._hasher

    def verify(self, password, encoded):
        return self.hasher.verify(password, self.to_orig(encoded))

    def encode(self, password, salt=None, **kwargs):
        if salt is not None:
            kwargs['salt'] = salt

        kwargs.update(getattr(settings, 'PASSLIB_KEYWORDS', {}).get(self.hasher.name, {}))

        if hasattr(self.hasher, 'using'):
            encoded = self.hasher.using(**kwargs).encrypt(password)
        else:  # passlib 1.6 does not have 'using'
            encoded = self.hasher.encrypt(password, **kwargs)

        return self.from_orig(encoded)

    def from_orig(self, hash):
        return '%s$%s' % (self.algorithm, hash)

    def to_orig(self, hash):
        return hash.split('$', 1)[1]

    def safe_summary(self, encoded):
        algorithm, hash = encoded.split('$', 1)
        assert algorithm == self.algorithm

        data = [(_('algorithm'), algorithm), ]
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
                        value = '%s%s' % ('?' * mask, '*' * (len(value) - mask))

                to_append.append((mapping, value))

        # parse any left-over fields:
        for key, value in parsed.items():
            data.append((_(key), value))

        return OrderedDict(data + to_append)


class PasslibCryptSchemeHasher(PasslibHasher):
    def from_orig(self, encrypted):
        return encrypted.lstrip('$')

    def to_orig(self, encoded):
        return '$%s' % encoded


########################
# Archaic Unix Schemes #
########################
class des_crypt(PasslibHasher):
    pass


class bsdi_crypt(PasslibHasher):
    pass


class bigcrypt(PasslibHasher):
    pass


class crypt16(PasslibHasher):
    pass


#########################
# Standard Unix Schemes #
#########################
class md5_crypt(PasslibHasher):
    pass


class sha1_crypt(PasslibHasher):
    pass


class sun_md5_crypt(PasslibHasher):
    pass


class sha256_crypt(PasslibHasher):
    pass


class sha512_crypt(PasslibHasher):
    pass


###############################
# Other Modular Crypt Schemes #
###############################
class apr_md5_crypt(PasslibCryptSchemeHasher):
    handler = 'apr_md5_crypt'
    algorithm = 'apr1'


class bcrypt_sha256(PasslibCryptSchemeHasher):
    handler = 'bcrypt_sha256'
    algorithm = 'bcrypt-sha256'


class phpass(PasslibHasher):
    pass


class pbkdf2_sha1(PasslibCryptSchemeHasher):
    handler = 'pbkdf2_sha1'
    algorithm = 'pbkdf2'


class pbkdf2_sha256(PasslibCryptSchemeHasher):
    handler = 'pbkdf2_sha256'
    algorithm = 'pbkdf2-sha256'


class pbkdf2_sha512(PasslibCryptSchemeHasher):
    handler = 'pbkdf2_sha512'
    algorithm = 'pbkdf2-sha512'


class cta_pbkdf2_sha1(PasslibHasher):
    pass


class dlitz_pbkdf2_sha1(PasslibHasher):
    pass


class scram(PasslibCryptSchemeHasher):
    pass


# bsd_nthash is provided by a converter

#########################
# Standard LDAP schemes #
#########################
# ldap_md5 is provided by a converter
# ldap_sha1 is provided by a converter
class ldap_salted_md5(PasslibHasher):
    pass


class ldap_salted_sha1(PasslibHasher):
    pass


# ldap_{crypt} provided by a converter
# ldap_plaintext makes no sense to support

#############################
# Non-Standard LDAP Schemes #
#############################
# ldap_hex_md5 is provided by a converter
# ldap_hex_sha1 is provided by a converter
# ldap_pbkdf2_{digest} is provided by a converter

class atlassian_pbkdf2_sha1(PasslibHasher):
    pass


class fshp(PasslibHasher):
    pass

# roundup_plaintext makes no sense to support


#######################
# SQL Database Hashes #
#######################
class mssql2000(PasslibHasher):
    pass


class mssql2005(PasslibHasher):
    pass


class mysql323(PasslibHasher):
    pass


class mysql41(PasslibHasher):
    pass

# postgres_md5 is incompatible (requires username for hash)
# oracle10 is incompatible (requires username for hash)


class oracle11(PasslibHasher):
    pass


#####################
# MS Windows Hashes #
#####################
class lmhash(PasslibHasher):
    pass


class nthash(PasslibHasher):
    pass

# msdcc is incompatible (requires username for hash)
# msdcc2 is incompatible (requires username for hash)


################
# Other hashes #
################
class cisco_pix(PasslibHasher):
    pass


class cisco_type7(PasslibHasher):
    pass

# django_{digest} not supported, for obvious reasons


class grub_pbkdf2_sha512(PasslibHasher):
    pass


class hex_md4(PasslibHasher):
    pass

# hex_md5 is already supported by Django
# hex_sha1 is already supported by Django


class hex_sha256(PasslibHasher):
    pass


class hex_sha512(PasslibHasher):
    pass


##########################
# Hashers added in 1.7.1 #
##########################

class argon2i(PasslibCryptSchemeHasher):
    """

    This hasher requires that you install the ``argon-cffi`` package.

    .. seealso:: https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html

    .. versionadded:: 0.4
    """
    handler = 'argon2'
    algorithm = 'argon2i'


class scrypt(PasslibCryptSchemeHasher):
    """

    This hasher requires that you install the ``scrypt`` package.

    .. seealso:: https://passlib.readthedocs.io/en/stable/lib/passlib.hash.scrypt.html

    .. versionadded:: 0.4
    """
    pass
