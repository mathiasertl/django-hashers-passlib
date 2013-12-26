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

from django.contrib.auth.hashers import BasePasswordHasher


class PasslibHasher(BasePasswordHasher):
    """Base class for all passlib-based hashers."""

    library = "passlib.hash"
    _hasher = None
    _algorithm = None
    hasher_name = None

    def salt(self):
        """Just return None, passlib handles salt-generation."""
        return None

    @property
    def algorithm(self):
        if self._algorithm is None:
            self._algorithm = self.__class__.__name__
        return self._algorithm

    @property
    def hasher(self):
        if self.hasher_name is None:
            self.hasher_name = self.__class__.__name__

        if self._hasher is None:
            self._hasher = getattr(self._load_library(), self.hasher_name)
        return self._hasher

    def verify(self, password, encoded):
        return self.hasher.verify(password, self.to_orig(encoded))

    def encode(self, password, salt=None):
        return self.from_orig(self.hasher.encrypt(password, salt=salt))


class ModularCryptHasher(PasslibHasher):
    """Base class for modular crypt schemes.

    Hashes generated/understood by this hasher look exactly like the original
    scheme except that the leading ``$`` is stripped.
    """
    def from_orig(self, hash):
        return hash.lstrip('$')

    def to_orig(self, hash):
        return '$%s' % hash


class RenamedModularCryptHasher(PasslibHasher):
    """Base class for modular crypt schemes where either the scheme name
    collides with a different scheme or the scheme is just a short number,
    making collisions with future hash schemes likely.

    Hashes generated/understood by this hasher look like the original hash
    but the leading ``$scheme`` is replaced by just ``new-name`` (without the
    leading ``$`` sign).
    """
    def from_orig(self, hash):
        return '%s$%s' % (self.algorithm, hash.lstrip('$').split('$', 1)[1])

    def to_orig(self, hash):
        return '$%s$%s' % (self.orig_scheme, hash.split('$', 1)[1])

class PrefixedModularCryptHasher(PasslibHasher):
    """Similar to the :py:class:`RenamedModularCryptHasher`, but prefixes
    a hash with the name of the algorithm.
    """
    def from_orig(self, encrypted):
        return '%s%s' % (self.algorithm, encrypted)

    def to_orig(self, encoded):
        return '$%s' % encoded.split('$', 1)[1]

class PrefixedHasher(PasslibHasher):
    """Base class for all schemes that are not modular crypt schemes. The
    original hash is prefixed with the algorithm and a ``$``.
    """
    def from_orig(self, hash):
        return '%s$%s' % (self.algorithm, hash)

    def to_orig(self, hash):
        return hash.split('$', 1)[1]


class PrefixedNoArgsHasher(PrefixedHasher):
    """Same as the PrefixedHasher but does not pass a salt."""
    def encode(self, password, salt=None):
        return self.from_orig(self.hasher.encrypt(password))


class des_crypt(PrefixedHasher):
    pass


class bsdi_crypt(PrefixedHasher):
    pass


class bigcrypt(PrefixedHasher):
    pass


class crypt16(PrefixedHasher):
    pass


class md5_crypt(RenamedModularCryptHasher):
    orig_scheme = '1'


class sha1_crypt(RenamedModularCryptHasher):
    orig_scheme = 'sha1'


class sun_md5_crypt(PrefixedModularCryptHasher):
    pass


class sha256_crypt(RenamedModularCryptHasher):
    orig_scheme = '5'


class sha512_crypt(RenamedModularCryptHasher):
    orig_scheme = '6'


class apr_md5_crypt(ModularCryptHasher):
    algorithm = 'apr1'


class phpass(PrefixedModularCryptHasher):
    pass


class cta_pbkdf2_sha1(PrefixedModularCryptHasher):
    pass


class dlitz_pbkdf2_sha1(PrefixedModularCryptHasher):
    pass


class scram(ModularCryptHasher):
    pass


class ldap_sha1(PrefixedNoArgsHasher):
    pass


class ldap_salted_md5(PrefixedHasher):
    pass


class ldap_salted_sha1(PrefixedHasher):
    pass


class ldap_hex_sha1(PrefixedNoArgsHasher):
    pass


class atlassian_pbkdf2_sha1(PrefixedHasher):
    pass


class fshp(PrefixedHasher):
    pass


class mssql2000(PrefixedHasher):
    pass


class mssql2005(PrefixedHasher):
    pass


class mysql323(PrefixedNoArgsHasher):
    pass


class mysql41(PrefixedNoArgsHasher):
    pass


class oracle11(PrefixedHasher):
    pass


class lmhash(PrefixedNoArgsHasher):
    pass


class nthash(PrefixedNoArgsHasher):
    pass


class cisco_pix(PrefixedNoArgsHasher):
    pass


class cisco_type7(PrefixedHasher):
    pass


class grub_pbkdf2_sha512(PrefixedHasher):
    pass


class hex_md4(PrefixedNoArgsHasher):
    pass


class hex_sha256(PrefixedNoArgsHasher):
    pass


class hex_sha512(PrefixedNoArgsHasher):
    pass
