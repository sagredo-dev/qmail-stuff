#!/bin/sh
#

CERTNAME=mx.mydomain.tld
CERTDIR=/etc/dehydrated/certs/${CERTNAME}
QMAILDIR=/var/qmail
QMAILCTL=/usr/local/bin/qmailctl
DOVECOTCTL=/usr/local/bin/dovecotctl
APACHECTL=/usr/sbin/apachectl
DEHYDRATED=/usr/bin/dehydrated

# cert renewal
$DEHYDRATED -c

if [ $? -eq 0 ]; then
  # qmail cert backup
  if [ ! -d "${QMAILDIR}/control/certs_backup" ]; then
    mkdir -p ${QMAILDIR}/control/certs_backup
  fi
  echo "Setting up the cert for qmail"
  cp -p ${QMAILDIR}/control/*.pem ${QMAILDIR}/control/certs_backup/
  cat ${CERTDIR}/privkey.pem ${CERTDIR}/fullchain.pem > ${QMAILDIR}/control/servercert.pem
  chown vpopmail:vchkpw ${QMAILDIR}/control/*.pem
  chmod o-r ${QMAILDIR}/control/*.pem
  # restart qmail
  $QMAILCTL restart

  # restart dovecot
  echo "Restarting dovecot"
  $DOVECOTCTL stop
  sleep 5
  $DOVECOTCTL start

  # restart apache
  echo "Restarting apache"
  $APACHECTL -k graceful

  exit 0
else exit 1
fi
