# Mailman Web configuration file.
# ~/etc/settings.py

# Get the default settings.
from mailman_web.settings.base import *
from mailman_web.settings.mailman import *

# Settings below supplement or override the defaults.

##############################
# https://docs.mailman3.org/en/latest/config-web.html#setting-up-email
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'localhost'
EMAIL_PORT = 25
#EMAIL_HOST_USER = <username>
#EMAIL_HOST_PASSWORD = <password>
##############################

#: Default list of admins who receive the emails from error logging.
ADMINS = (
    ('Mailman Suite Admin', 'admin@sagredo.eu'),
)

# Postgresql database setup.
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'mailman_web',
        'USER': 'mailman',
        # TODO: Replace this with the password.
        'PASSWORD': 'password',
        'HOST': 'localhost',
#        'PORT': '3306',
        'OPTIONS': {
            # https://gitlab.com/mailman/hyperkitty/-/issues/248
            # Set sql_mode to 'STRICT_TRANS_TABLES' for MySQL. See
            # https://docs.djangoproject.com/en/1.11/ref/databases/#setting-sql-mode
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
            'charset': 'utf8mb4',
        }
    }
}

# 'collectstatic' command will copy all the static files here.
# Alias this location from your webserver to `/static`
STATIC_ROOT = '/usr/local/mailman/web/static'

# enable the 'compress' command.
COMPRESS_ENABLED = True

# Make sure that this directory is created or Django will fail on start.
LOGGING['handlers']['file']['filename'] = '/usr/local/mailman/web/logs/mailmanweb.log'
# Mailman Suite project in Gitlab disables sending of emails when DEBUG=True is set
# and instead prints the emails to a directory emails under mailman-suite_project.
# If you don’t see any outgoing emails, set DEBUG=False.
#DEBUG=False

#: See https://docs.djangoproject.com/en/dev/ref/settings/#allowed-hosts
ALLOWED_HOSTS = [
    "localhost",  # Archiving API from Mailman, keep it.
    "127.0.0.1",
    "0.0.0.0",
    "lists.mydomain.tld",
    # Add here all production domains you have.
]

#: See https://docs.djangoproject.com/en/dev/ref/settings/#csrf-trusted-origins
#: For Django <4.0 these are of the form 'lists.example.com' or
#: '.example.com' to include subdomains and for Django >=4.0 they include
#: the scheme as in 'https://lists.example.com' or 'https://*.example.com'.
CSRF_TRUSTED_ORIGINS = [
    "http://lists.mydomain.tld",
    "https://lists.mydomain.tld",
    # Add here all production domains you have.
]

#: Current Django Site being served. This is used to customize the web host
#: being used to serve the current website. For more details about Django
#: site, see: https://docs.djangoproject.com/en/dev/ref/contrib/sites/
SITE_ID = 2

# Set this to a new secret value.
SECRET_KEY = 'xxxxxxxxxxxxxxxxxxxxxxxxxxx'

# Set this to match the api_key setting in
# ~/etc/mailman-hyperkitty.cfg (quoted here, not there).
MAILMAN_ARCHIVER_KEY = 'xxxxxxxxxxxxxxxxxxxxxxxxxxx'

# The sender of emails from Django such as address confirmation requests.
# Set this to a valid email address.
DEFAULT_FROM_EMAIL = 'postmaster@mydomain.tld'

# The sender of error messages from Django. Set this to a valid email
# address.
SERVER_EMAIL = 'postmaster@mydomain.tld'

# Localization
USE_I18N = True
LANGUAGE_CODE = "en-en"

# memcached fixes an issue which prevented the deletion of items from the archive
# https://gitlab.com/mailman/hyperkitty/-/issues/504#note_1937343226
# Using the cache infrastructure can significantly improve performance on a
# production setup. This is an example with a local Memcached server.
# you need to install pylibmc and memcached. Use as an alternative of diskcache
# pip install pylibmc
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.PyLibMCCache',
        'LOCATION': '127.0.0.1:11211',
    }
}

# diskcache
# pip install diskcache
#DISKCACHE_PATH = os.environ.get('DISKCACHE_PATH', '/usr/local/mailman/web/diskcache')
#DISKCACHE_SIZE = os.environ.get('DISKCACHE_SIZE', 2 ** 30) # 1 gigabyte
#CACHES = {
#    'default': {
#        'BACKEND': 'diskcache.DjangoCache',
#        'LOCATION': DISKCACHE_PATH,
#        'OPTIONS': {
#            'size_limit': DISKCACHE_SIZE,
#        },
#    },
#}

# xapian (full text search)
HAYSTACK_CONNECTIONS = {
   'default': {
       'HAYSTACK_XAPIAN_LANGUAGE': 'en',
       'ENGINE': 'xapian_backend.XapianEngine',
       'PATH': "/usr/local/mailman/web/xapian_index"
   },
}
