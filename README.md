`django-hashers-passlib` aims to make password hashing schemes provided by
[passlib](https://passlib.readthedocs.io/en/stable/) usable in [Django](https://www.djangoproject.com/).
Unlike passlibs
[passlib.ext.django](https://pythonhosted.org/passlib/lib/passlib.ext.django.html#module-passlib.ext.django),
it does not replace Djangos [password management
system](https://docs.djangoproject.com/en/dev/topics/auth/passwords/) but provides standard hashers that can
be added to the `PASSWORD_HASHERS` setting for hash schemes provided by passlib.

There are two primary usecases for this module:

1. You want to import password hashes from an existing application into your Django database.
2. You want to export password hashes to a different application in the future.

Installation
------------

This module is available via pip, install it with

    pip install django-hashers-passlib

It requires Django >= 1.8 (earlier versions might work) and passlib >= 1.6.2. It supports Python versions 2.7
and 3.4 or later.

Getting started
---------------

This module supports almost every hash supported by passlib (some must be converted at first - see below). If
you want your Django project app to understand hashes provided by passlib, simply add the hashers to the
[PASSWORD_HASHERS](https://docs.djangoproject.com/en/dev/ref/settings/#std:setting-PASSWORD_HASHERS) setting.
Note that the first value is the default hasher, so if you want to store new user passwords in one of these
hashes, prepend the hash to the list:

```
PASSWORD_HASHERS = [
    # new user passwords should be stored in the phpass format
    'hashers_passlib.phpass',

    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    # ... other Django hashers

    # We also want to add some users from say mssql2000 (who wouldn't?)
    'hashers_passlib.mssql2000',
]
```

Almost every module in passlib has hasher with the same name, see "Supported hashes" below for full list.

You can also configure default parameters for different hash algorithms, for example to configure a different
number of rounds for `pbkdf2_sha256`:

```
PASSLIB_KEYWORDS = {
    'pbkdf2_sha256': {
        'rounds': 32000,
    },
}
```

The documentation for passlib contains a list of available parameters.

Import/Export
-------------

Django dictates a scheme for storing passwords (see [How Django stores
passwords](https://docs.djangoproject.com/en/dev/topics/auth/passwords/#auth-password-storage). Some hashes
are stored simply by prefixing the hash name, others already almost fit into the scheme and only their leading
`$` is stripped.

If you want to import hashes from another application into Djangos hash encoding scheme (see "How it works
interally" below for details), every hasher has a `from_orig()` and `to_orig()` method, which allows to
import/export hashes. So importing a user from a different system is simply a matter of calling `from_orig()`
of the right hasher and save that to the `password` field of Djangos `User` model. Here is a simple example:

```python
# Lets import a phpass (WordPress, phpBB3, ...) hash. This assumes that you have 'hashers_passlib.phpass' in
# your PASSWORD_HASHERS setting.

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import get_hasher

User = get_user_model()  # get any custom user model

hasher = get_hasher('phpass')

# you got this from i.e. a WordPress database:
raw_hashes = {
    'joe': '$P$EnOjUf5ie1AeWMHpw1dqHUQYHAIBe41',
    'jane': '$P$E6UROQJscRzZ3ve2hoIFZ1OcjBA1W10',
}

for username, hash in raw_hashes.items():
    user = User.objects.create(username=username)
    user.password = hasher.from_orig(hash)
    user.save()
```

The users "joe" and "jane" can now login with their old usernames and passwords. 

If you want to export users with a phpass hash to a WordPress database again, you can simple get the original
hashes back (for simplicity, we just print everything to stdout here):

```python
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import get_hasher

User = get_user_model()  # get any custom user model

hasher = get_hasher('phpass')

for user in User.objects.filter(password__startswith='phpass$'):
    orig_hash = hasher.to_orig(user.password)
    print('%s has hash "%s"' % (user.username, orig_hash))
```

Supported hashes
----------------

This module provides hashers for most hash schemes provided by passlib - but remember you have to import them
using the hashers `from_orig()` method first to be useable. Some have to be be converted first (see below),
and only a few minor old hashes are not supported. All password hashers have the same class name as the
passlib hasher they wrap and are located in the `hashers_passlib` module. So to enable support for e.g.
`sha1_crypt` hashes, add `hashers_passlib.sha1_crypt` to your `PASSWORD_HASHERS` Django setting.

**WARNING:** Some hashes are longer then the 128 characters provided by the standard User model provided by
Django. You have to specify a [custom user
model](https://docs.djangoproject.com/en/dev/topics/auth/customizing/#specifying-a-custom-user-model) with at
least 256 characters for `hex_sha512`, `pbkdf2_sha512`, `scram` and `sha512_crypt` or at least 384 characters
for `grub_pbkdf2_sha512`.

The following algorithms are supported: 
[des_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.des_crypt.html),
[bsdi_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.bsdi_crypt.html),
[bigcrypt](https://pythonhosted.org/passlib/lib/passlib.hash.bigcrypt.html),
[crypt16](https://pythonhosted.org/passlib/lib/passlib.hash.crypt16.html),
[md5_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.md5_crypt.html),
[sha1_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.sha1_crypt.html),
[sun_md5_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.sun_md5_crypt.html),
[sha256_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.sha256_crypt.html),
[sha512_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.sha512_crypt.html),
[apr_md5_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.apr_md5_crypt.html),
[bcrypt_sha256](https://pythonhosted.org/passlib/lib/passlib.hash.bcrypt_sha256.html),
[phpass](https://pythonhosted.org/passlib/lib/passlib.hash.phpass.html),
[pbkdf2_&lt;digest&gt;](https://pythonhosted.org/passlib/lib/passlib.hash.pbkdf2_digest.html),
[dlitz_pbkdf2_sha1](https://pythonhosted.org/passlib/lib/passlib.hash.dlitz_pbkdf2_sha1.html),
[cta_pbkdf2_sha1](https://pythonhosted.org/passlib/lib/passlib.hash.cta_pbkdf2_sha1.html),
[scram](https://pythonhosted.org/passlib/lib/passlib.hash.scram.html),
[ldap_salted_md5](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_std.html#passlib.hash.ldap_salted_md5),
[ldap_salted_sha1](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_std.html#passlib.hash.ldap_salted_sha1),
[atlassian_pbkdf2_sha1](https://pythonhosted.org/passlib/lib/passlib.hash.atlassian_pbkdf2_sha1.html),
[fshp](https://pythonhosted.org/passlib/lib/passlib.hash.fshp.html),
[mssql2000](https://pythonhosted.org/passlib/lib/passlib.hash.mssql2000.html),
[mssql2005](https://pythonhosted.org/passlib/lib/passlib.hash.mssql2005.html),
[mysql323](https://pythonhosted.org/passlib/lib/passlib.hash.mysql323.html),
[mysql41](https://pythonhosted.org/passlib/lib/passlib.hash.mysql41.html),
[oracle11](https://pythonhosted.org/passlib/lib/passlib.hash.oracle11.html),
[lmhash](https://pythonhosted.org/passlib/lib/passlib.hash.lmhash.html),
[nthash](https://pythonhosted.org/passlib/lib/passlib.hash.nthash.html),
[cisco_pix](https://pythonhosted.org/passlib/lib/passlib.hash.cisco_pix.html),
[cisco_type7](https://pythonhosted.org/passlib/lib/passlib.hash.cisco_type7.html),
[grub_pbkdf2_sha512](https://pythonhosted.org/passlib/lib/passlib.hash.grub_pbkdf2_sha512.html),
[hex_{md4,sha256,sha512}](https://pythonhosted.org/passlib/lib/passlib.hash.hex_digests.html),
[argon2](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html),
and
[scrypt](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.scrypt.html)

Most hashes will be saved with a simple prefix `<algorithm>$`, where "&lt;algorithm&gt;" is the name of the
hasher. The only exception are a few hashes (`apr_md5_crypt`, `bcrypt_sha256`, `pbkdf2_<digest>`, `scram`)
that already almost fit into Djangos hash scheme, where only the leading `$` is stripped.

**NOTE:** Some hashes (`bcrypt_sha256`, `pbkdf2_<digest>`, ...) look very similar to what Django provides but
are actually distinct algorithms.

Hashes supported via conversion
-------------------------------

Some hash schemes really are just a minor transformation of a different hash scheme. For example, the
[bsd_nthash](https://pythonhosted.org/passlib/lib/passlib.hash.nthash.html#passlib.hash.bsd_nthash) is just a
regular [nthash](https://pythonhosted.org/passlib/lib/passlib.hash.nthash.html#passlib.hash.nthash) with
`$3$$` prepended and the
[ldap_md5](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_std.html#passlib.hash.ldap_md5) has is just
a plain MD5 hash with `{MD5}` prepended that is already supported by Django. 

In order to avoid code duplication, this module does not provide password hashers for these schemes, but
converters under `hashers_passlib.converters`.  Converted hashes are either readable by a different hasher or
by a hasher provided by Django.

If you want to import `bsd_nthash` hashes, you can either manually strip the identifier or use the converter:

```python
# Lets import bsd_nthash hashes as plain nthash hashes. This assumes you have
# have 'hashers_passlib.nthash' in your PASSWORD_HASHERS setting.

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import get_hasher

from hashers_passlib.converters import bsd_nthash

conv = bsd_nthash()

raw_hashes = {
    'joe': '$3$$baac3929fabc9e6dcd32421ba94a84d4',
}

for username, hash in raw_hashes.items():
    user = User.objects.create(username=username)

    # convert bsd_nthash to plain nthash:
    user.password = converter.from_orig(hash)
    user.save()

```

The following converters are available under `hashers_passlib.converters`, they
can be used to convert from and to the original scheme:

From | To | Notes
--- | --- | ---
[bcrypt](https://pythonhosted.org/passlib/lib/passlib.hash.bcrypt.html) | `BCryptPasswordHasher` | Converted to bcrypt hash supported by the stock Django hasher.
[bsd_nthash](https://pythonhosted.org/passlib/lib/passlib.hash.nthash.html#passlib.hash.bsd_nthash) | `nthash` | Convert from bsd_nthash to nthash and vice versa.
[ldap_md5](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_std.html#passlib.hash.ldap_md5) | `UnsaltedMD5PasswordHasher` | Converted to plain MD5 hash supported by Django.
[ldap_sha1](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_std.html#passlib.hash.ldap_sha1) | `UnsaltedSHA1PasswordHasher` | Converted to plain SHA1 hash supported by Django.
[ldap_hex_md5](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_other.html#passlib.hash.ldap_hex_md5) | `UnsaltedMD5PasswordHasher` | Converted to plain MD5 hash supported by Django.
[ldap_hex_sha1](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_other.html#passlib.hash.ldap_hex_sha1) | `UnsaltedSHA1PasswordHasher` | Converted to plain SHA1 hash supported by Django.
[ldap_{crypt}](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_crypt.html) | various | Converted to their non-LDAP pendants (i.e. `ldap_des_crypt` is converted to a plain `des_crypt` hash).
[ldap_bcrypt](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_crypt.html) | `BCryptPasswordHasher` | Unlike other ldap_{crypt} schemes, ldap_bcrypt hashes are converted to what Djangos stock BCrypt hashser understands.
[ldap_pbkdf2_{digest}](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_pbkdf2_digest.html) | `pbkdf2_{digest}` | Converted to their non-LDAP pendants.

Unsupported hashes
------------------

Some hashes are unsupported because they require the username to generate the salt: 
[postgres_md5](https://pythonhosted.org/passlib/lib/passlib.hash.postgres_md5.html),
[oracle10](https://pythonhosted.org/passlib/lib/passlib.hash.oracle10.html),
[msdcc](https://pythonhosted.org/passlib/lib/passlib.hash.msdcc.html) and
[msdcc2](https://pythonhosted.org/passlib/lib/passlib.hash.msdcc2.html).

How it works internally
-----------------------

Djangos password management system stores passwords in a format that is very similar but still distinct from
what passlib calls [Modular Crypt
Format](https://pythonhosted.org/passlib/modular_crypt_format.html#modular-crypt-format):

    <algorithm>$<content>

... where "&lt;algorithm&gt;" is the identifier used to select what hasher class should handle the hash. The
only difference to the Modular Crypt Format is that it misses the leading `$` sign. Note that the `$` in the
middle is a mandatory delimiter.

This module modifies the hash schemes so they fit into this scheme before storing them in the database. The
modifications are absolutely reversible - in fact this module depends on it being reversible, our hashers
won't work any other way. Depending on the original hash scheme, the hashes are modified in one of several
ways:

1. Some old and insecure hashes require the username to encode the hash.  Djangos hashers don't receive the
   username, so they are not compatible and not supported by this module.
2. Some of passlibs hashes are already supported by Django and the functionality is not duplicated here.
3. Some hash schemes are really just minor modifications of different schemes, we provide converters in this
   case.
4. A few hashes already almost fit in Djangos scheme and have a reasonably unique identifier, they just have
   the leading `$` stripped.
5. All other hashes (which is the vast majority!) just have `<identifier>$` prepended. This is the same
   approach as what Django does with e.g. bcrypt hashes.
