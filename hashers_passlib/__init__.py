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
    def from_orig(self, hash):
        return hash.lstrip('$')

    def to_orig(self, hash):
        return '$%s' % hash


class RenamedModularCryptHasher(PasslibHasher):
    def from_orig(self, hash):
        return '%s$%s' % (self.algorithm, hash.lstrip('$').split('$', 1)[1])

    def to_orig(self, hash):
        return '$%s$%s' % (self.orig_scheme, hash.split('$', 1)[1])

class PrefixedModularCryptHasher(PasslibHasher):
    def from_orig(self, encrypted):
        return '%s%s' % (self.algorithm, encrypted)

    def to_orig(self, encoded):
        return '$%s' % encoded.split('$', 1)[1]

class PrefixedHasher(PasslibHasher):
    def from_orig(self, hash):
        return '%s$%s' % (self.algorithm, hash)

    def to_orig(self, hash):
        return hash.split('$', 1)[1]


class des_crypt(PrefixedHasher):
    pass


class bsdi_crypt(PrefixedHasher):
    pass


class bigcrypt(PrefixedHasher):
    pass


class crypt16(PrefixedHasher):
    pass


class md5_crypt(PrefixedHasher):
    pass


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
