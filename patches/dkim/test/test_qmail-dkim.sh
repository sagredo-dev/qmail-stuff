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
    CONTROLDIR=/tmp/control \
	DKIMSIGN=/var/qmail/control/domainkeys/%/${RSA2048_SELECTOR} \
	DKIMSIGNOPTIONS="-z 2" \
	DKIMSIGNEXTRA=/var/qmail/control/domainkeys/%/${ED25519_SELECTOR} \
	DKIMSIGNOPTIONSEXTRA="-z 4" \
	DKIMQUEUE=/bin/cat \
	/var/qmail/bin/qmail-dkim < /tmp/mail.txt
