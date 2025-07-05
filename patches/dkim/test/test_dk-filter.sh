#!/bin/bash

DOMAIN=domain.tld
RSA2048_SELECTOR=default
#RSA2048_SELECTOR=rsa2048
ED25519_SELECTOR=ed25519

(
echo "From: postmaster@${DOMAIN}"
echo "To: postmaster@${DOMAIN}"
echo "Subject: Test"
echo "Date: $(date -R)"
echo
echo "Test message"
) > /tmp/mail.txt

sudo -u qmailr env - \
    QMAILREMOTE="1" \
    _SENDER=postmaster@${DOMAIN} \
    CONTROLDIR=/tmp/control \
    DKIMSIGN=/var/qmail/control/domainkeys/%/${RSA2048_SELECTOR} \
    DKIMSIGNOPTIONS="-z 2" \
    DKIMSIGNEXTRA=/var/qmail/control/domainkeys/%/${ED25519_SELECTOR} \
    DKIMSIGNOPTIONSEXTRA="-z 4" \
    /var/qmail/bin/dk-filter < /tmp/mail.txt
