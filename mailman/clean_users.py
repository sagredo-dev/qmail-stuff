#! /usr/local/mailman/bin/python

# Copyright (C) 2023 by the Free Software Foundation, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.

"""
This script will delete Django users for which there is no corresponding
Mailman user or optionally a Mailman user with no list memberships. It can
also optionally delete Mailman users with no list memberships.
"""

import os
import sys

# Set the path to the directory containing settings.py and mailman.cfg.
# For a setup following
# https://docs.mailman3.org/en/latest/install/virtualenv.html set
# CFG_PATH = '/etc/mailman3'
# For some older setups set
# CFG_PATH = '/opt/mailman/mm'
CFG_PATH = '/usr/local/mailman/etc'

# Set True to delete Mailman users that have no memberships with any role.
# Set False to not delete Mailman users.
DELETE_MAILMAN_USER = True

# Set True to delete the Django user if there is a Mailman user with no
# memberships.
# Set False to delete the Django user only if there is no Mailman user.
DELETE_DJANGO_IF_MAILMAN = True

sys.path.insert(0, CFG_PATH)
# The above line is required. The next line doesn't hurt, but it doesn't work
# because the PYTHONPATH environment setting is processed by Python's setup
# and must be in the environment when Python starts to be effective.
os.environ['PYTHONPATH'] = CFG_PATH
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
os.environ['MAILMAN_CONFIG_FILE'] = os.path.join(CFG_PATH, 'mailman.cfg')

import django
django.setup()

from django.contrib.auth.models import User
from mailman.core import initialize
from mailman.database.transaction import transaction
from mailman.interfaces.usermanager import IUserManager
from zope.component import getUtility

initialize.initialize()

user_manager = getUtility(IUserManager)
for django_user in User.objects.all():
    mm_user = user_manager.get_user(django_user.email)
    if mm_user is None or (DELETE_DJANGO_IF_MAILMAN and
                           len(list(mm_user.memberships.members)) == 0):
        # No mailman user for this address or DELETE_DJANGO_IF_MAILMAN is True
        # and user is not a member, nonmember, owner or moderator of any list.
        User.objects.filter(email=django_user.email).delete()
        print('User with email {} deleted from Django'.format(
              django_user.email))
if DELETE_MAILMAN_USER:
    for mm_user in user_manager.users:
        if len(list(mm_user.memberships.members)) == 0:
            with transaction():
                name = mm_user.display_name
                try:
                    email = mm_user.preferred_address.email
                except AttributeError:
                    try:
                        email = mm_user.addresses[0].email
                    except AttributeError:
                        email = 'no_email'
                user_manager.delete_user(mm_user)
                print(f'User: "{name}" <{email}> deleted from Mailman')
