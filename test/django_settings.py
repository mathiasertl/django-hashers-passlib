# Basic django settings

DEBUG = True
SECRET_KEY = 'dummy'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}
