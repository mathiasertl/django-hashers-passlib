`django-hashers-passlib` aims to make password hashing schemes provided by
[passlib](https://pythonhosted.org/passlib/) usable in
[Django](https://www.djangoproject.com/). It provides standard Django password
hashers that dynamically prefix the hashes returned, but use passlib
internally. There are two schenarios where you might want to use hashes used by
applications other then Django in your Django application:

1. You want to import password hashes from an existing application into your
   Django database.
2. You want to export password hashes to a different application in the
   future.
