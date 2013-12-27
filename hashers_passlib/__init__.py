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
        return getattr(self._load_library(), self.algorithm)

    def verify(self, password, encoded):
        return self.hasher.verify(password, self.to_orig(encoded))

    def encode(self, password, salt=None):
        return self.from_orig(self.hasher.encrypt(password))

    def from_orig(self, hash):
        return '%s$%s' % (self.algorithm, hash)

    def to_orig(self, hash):
        return hash.split('$', 1)[1]


class des_crypt(PasslibHasher):
    pass


class bsdi_crypt(PasslibHasher):
    pass


class bigcrypt(PasslibHasher):
    pass


class crypt16(PasslibHasher):
    pass


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


class apr_md5_crypt(PasslibHasher):
    pass


class phpass(PasslibHasher):
    pass


class cta_pbkdf2_sha1(PasslibHasher):
    pass


class dlitz_pbkdf2_sha1(PasslibHasher):
    pass


class scram(PasslibHasher):
    pass


class ldap_salted_md5(PasslibHasher):
    pass


class ldap_salted_sha1(PasslibHasher):
    pass


class atlassian_pbkdf2_sha1(PasslibHasher):
    pass


class fshp(PasslibHasher):
    pass


class mssql2000(PasslibHasher):
    pass


class mssql2005(PasslibHasher):
    pass


class mysql323(PasslibHasher):
    pass


class mysql41(PasslibHasher):
    pass


class oracle11(PasslibHasher):
    pass


class lmhash(PasslibHasher):
    pass


class nthash(PasslibHasher):
    pass


class cisco_pix(PasslibHasher):
    pass


class cisco_type7(PasslibHasher):
    pass


class grub_pbkdf2_sha512(PasslibHasher):
    pass


class hex_md4(PasslibHasher):
    pass


class hex_sha256(PasslibHasher):
    pass


class hex_sha512(PasslibHasher):
    pass
