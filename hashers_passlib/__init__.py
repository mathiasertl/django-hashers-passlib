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
        if self._hasher is None:
            self._hasher = getattr(self._load_library(), self.algorithm)
        return self._hasher


class ModularCryptHasher(PasslibHasher):
    def verify(self, password, encoded):
        return self.hasher.verify(password, '$%s' % encoded)

    def encode(self, password, salt=None):
        return self.hasher.encrypt(password, salt=salt)[1:]

    def from_orig(self, hash):
        return hash.lstrip('$')

    def to_orig(self, hash):
        return '$%s' % hash


class RenamedModularCryptHasher(PasslibHasher):
    def verify(self, password, encoded):
        _algo, hash = encoded.split('$', 1)
        encoded = '$%s$%s' % (self.orig_scheme, hash)
        return self.hasher.verify(password, encoded)

    def encode(self, password, salt=None):
        encrypted = self.hasher.encrypt(password, salt=salt)
        encoded = encrypted.lstrip('$').split('$', 1)[1]
        return '%s$%s' % (self.algorithm, encoded)

    def from_orig(self, hash):
        return '%s$%s' % (self.algorithm, hash.lstrip('$').split('$', 1)[1])

    def to_orig(self, hash):
        return '$%s$%s' % (self.orig_scheme, hash.split('$', 1)[1])


class PrefixedHasher(PasslibHasher):
    def verify(self, password, encoded):
        _algo, hash = encoded.split('$', 1)
        return self.hasher.verify(password, hash)

    def encode(self, password, salt):
        encoded = self.hasher.encrypt(password)
        return '%s$%s' % (self.algorithm, encoded)

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
