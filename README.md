`django-hashers-passlib` aims to make password hashing schemes provided by
[passlib](https://pythonhosted.org/passlib/) usable in
[Django](https://www.djangoproject.com/). Unlike passlibs
[passlib.ext.django](https://pythonhosted.org/passlib/lib/passlib.ext.django.html#module-passlib.ext.django),
it does not replace Djangos [password management
system](https://docs.djangoproject.com/en/dev/topics/auth/passwords/) but
provides standard hashers that can be added to the `PASSWORD_HASHERS` setting
for hash schemes provided by passlib.

There are two primary usecases for this module:

1. You want to import password hashes from an existing application into your
   Django database.
2. You want to export password hashes to a different application in the
   future.

Getting started
---------------

This module supports almost every hash supported by passlib (some must be
converted at first - see below), but hashes must be slightly modified in order
to fit into Djangos hash encoding scheme (see "How it works interally" below
for details).  Every hasher class is named like the module provided by passlib
and every hash has a `from_orig()` and `to_orig()` method, which allows to
import/export hashes. So importing a user from a different system is simply a
matter of calling `from_orig()` of the right hasher and save that to the
`password` field of Djangos `User` model. Here is a simple example:

```python
# Lets import a phpass (WordPress, phpBB3, ...) hash. This assumes that you
# have 'hashers_passlib.phpass' in your PASSWORD_HASHERS setting.

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

The users "joe" and "jane" can now login with their old usernames and
passwords. If you want to export users with a phpass hash to a WordPress
database again, you can simple get the original hashes back (for simplicity, we
just print everything to stdout here):

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

The following password hashers are available in this module:

Algorithm | Notes
--- | --- 
[des_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.des_crypt.html)</td> | Prefixed with `des_crypt$`.
[bsdi_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.bsdi_crypt.html) | Prefixed with `bsdi_crypt$`.
[bigcrypt](https://pythonhosted.org/passlib/lib/passlib.hash.bigcrypt.html) | Prefixed with `bigcrypt$`.
[crypt16](https://pythonhosted.org/passlib/lib/passlib.hash.crypt16.html) | Prefixed with `crypt16$`.
[md5_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.md5_crypt.html) | Use the identifier `md5_crypt$` instead of the `$1$`.
[bcrypt](https://pythonhosted.org/passlib/lib/passlib.hash.bcrypt.html) | Already supported by Django, so not implemented here.
[sha1_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.sha1_crypt.html) | Use the identifier `sha1_crypt$` instead of `$sha1$`, since `sha1$` is already used by an old Django hasher.
[sun_md5_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.sun_md5_crypt.html) | The identifier already encodes the number of rounds, so hashes are prefixed with the additional identifier `sun_md5_crypt$`.
[sha256_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.sha256_crypt.html) | Use the identifier `sha256_crypt$` instead of `$5$`.
[sha512_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.sha512_crypt.html) | Use the identifier `sha512_crypt$` instead of `$5$`.
[apr_md5_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.apr_md5_crypt.html) | Only the leading `$` is stripped, so hashes will start with `apr1$`.
[phpass](https://pythonhosted.org/passlib/lib/passlib.hash.phpass.html) | Since different implementations use different prefixes, the identifier `phpass$` is prepended.
[pbkdf2_&lt;digest&gt;](https://pythonhosted.org/passlib/lib/passlib.hash.pbkdf2_digest.html) | Already supported by Django, so not implemented here.
[dlitz_pbkdf2_sha1](https://pythonhosted.org/passlib/lib/passlib.hash.dlitz_pbkdf2_sha1.html) | Because `cta_pbkdf2_sha1` uses the same identifier, `dlitz_pbkdf2_sha1$` is prepended.
[cta_pbkdf2_sha1](https://pythonhosted.org/passlib/lib/passlib.hash.cta_pbkdf2_sha1.html) | Because `dlitz_pbkdf2_sha1` uses the same identifier, `cta_pbkdf2_sha1$` is prepended.
[scram](https://pythonhosted.org/passlib/lib/passlib.hash.scram.html) | Only the leading `$` is stripped, so hashes will start with `scram$`.
[ldap_salted_md5](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_std.html#passlib.hash.ldap_salted_md5) | Prefixed with `ldap_salted_md5$`.
[ldap_salted_sha1](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_std.html#passlib.hash.ldap_salted_sha1) | Prefixed with `ldap_salted_sha1$`.
[ldap_crypt_&lt;digest&gt;](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_crypt.html) | Just a prefix to regular crypt schemes, so please strip the prefix and import as regular hashers.
[ldap_pbkdf2_&lt;digest&gt>](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_pbkdf2_digest.html) | These hashes are standard PBKDF2 hashes and are essentially already supported by Django. Just replace i.e. `{PBKDF2}` with `PBKDF2$`.
[atlassian_pbkdf2_sha1](https://pythonhosted.org/passlib/lib/passlib.hash.atlassian_pbkdf2_sha1.html) | Prefixed with `atlassian_pbkdf2_sha1`.
[fshp](https://pythonhosted.org/passlib/lib/passlib.hash.fshp.html) | Prefixed with `fshp$`.

Hashes supported via conversion
-------------------------------

Some hash schemes really are just a minor transformation of a different hash
scheme. For example, the
[bsd_nthash](https://pythonhosted.org/passlib/lib/passlib.hash.nthash.html#passlib.hash.bsd_nthash)
is just a regular
[nthash](https://pythonhosted.org/passlib/lib/passlib.hash.nthash.html#passlib.hash.nthash)
with `$3$$` prepended.  In order to avoid code duplication, this module does
not provide password hashers for these schemes, but converters under
`hashers_passlib.converters`. Converted hashes are either readable by a
different hasher or by a hasher provided by Django. In the latter case you can
save the converted value directly to the users `password` field.

If you want to import `bsd_nthash` hashes, you can either manually strip the
identifier or use our converter:

```python
# Lets import bsd_nthash hashes as plain nthash hashes. This assumes you have
# have 'hashers_passlib.nthash' in your PASSWORD_HASHERS setting.

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import get_hasher

from hashers_passlib.converters import bsd_nthash

hasher = get_hasher('phpass')
conv = bsd_nthash()

raw_hashes = {
    'joe': '$3$$baac3929fabc9e6dcd32421ba94a84d4',
}

for username, hash in raw_hashes.items():
    user = User.objects.create(username=username)

    # convert bsd_nthash to plain nthash:
    nthash_hash = converter.from_orig(hash)

    # proceed as before:
    user.password = hasher.from_orig(hash)
    user.save()

```

The following converters are available under `hashers_passlib.converters`, they
can be used to convert from and to the original scheme:

From | To | Notes
--- | --- | ---
[bsd_nthash](https://pythonhosted.org/passlib/lib/passlib.hash.nthash.html#passlib.hash.bsd_nthash) | [nthash](https://pythonhosted.org/passlib/lib/passlib.hash.nthash.html#passlib.hash.nthash) | Convert from bsd_nthash to nthash and vice versa.
[ldap_md5](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_std.html#passlib.hash.ldap_md5) | - | Converted to plain MD5 hash supported by Django.
[ldap_sha1](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_std.html#passlib.hash.ldap_sha1) | - | Converted to plain SHA1 hash supported by Django.
[ldap_hex_md5](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_other.html#passlib.hash.ldap_hex_md5) | - | Converted to plain MD5 hash supported by Django.
[ldap_hex_sha1](https://pythonhosted.org/passlib/lib/passlib.hash.ldap_other.html#passlib.hash.ldap_hex_sha1) | - | Converted to plain SHA1 hash supported by Django.

Unsupported hashes
------------------

Some hashes are unsupported:

Algorithm | Reason
--- | ---
[msdcc](https://pythonhosted.org/passlib/lib/passlib.hash.msdcc.html) | Scheme requires a username to generate a salt.

How it works internally
-----------------------

Djangos password management system stores passwords in a format that is very
similar but still distinct from what passlib calls [Modular Crypt
Format](https://pythonhosted.org/passlib/modular_crypt_format.html#modular-crypt-format):

    <algorithm>$<content>

... where "&ltlalgorithm&gt;" is the identifier used to select what hasher
class should handle the hash. The only difference to the Modular Crypt Format
is that it misses the leading `$` sign. Note that the `$` in the middle is a
mandatory delimiter.

This module modifies the hash schemes so they fit into this scheme before
storing them in the database. The modifications are absolutely reversible - in
fact this module depends on it being reversible, our hashers won't work any
other way. Depending on the original hash scheme, the hashes are modified in
one of several ways:

1. Some "standard" modular crypt hashes just have the leading `$` stripped.
2. Some modular crypt hash schemes with ambiguous identifiers (like `$1$` for
   md5_crypt or even `$sha1$`) have a different identifier to make them unique.
3. Some modular crypt hashes (such as
   [sun_md5_crypt](https://pythonhosted.org/passlib/lib/passlib.hash.sun_md5_crypt.html))
   encode information in their identifier, so they are prefixed with another
   identifier so the identifier is consistent.
4. All hashes that don't follow the modular crypt scheme have `<identifier>$
   prepended.
5. Some old and insecure hashes require the username to encode the hash.
   Djangos hashers don't receive the username, so they are not compatible with
   this approach.
6. Some of passlibs hashes are already supported by Django and the
   functionality is not duplicated here.
