#!/bin/bash

DOMAIN=domain.tld

(
echo "From: postmaster@${DOMAIN}"
echo "To: postmaster@${DOMAIN}"
echo "Subject: Test"
echo "Date: $(date -R)"
echo
echo "Test message"
) > /tmp/mail.txt

sudo -u vpopmail env - \
DKIMQUEUE=/bin/cat \
/var/qmail/bin/qmail-dkim < /tmp/mail.txt
