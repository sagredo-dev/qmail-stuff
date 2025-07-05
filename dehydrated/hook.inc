#!/usr/bin/env bash

# Configuration for the script:
CONF_FILE="$(dirname $0)/$(basename $0 .sh).conf"
[ -f ${CONF_FILE} ] && . ${CONF_FILE}

send_alert()
{
  # Send email alert to admin $1 is DOMAIN

  CERT_PATH=/etc/dehydrated/certs/$1/cert.pem
  EXPIRY=$(openssl x509 -noout -dates -in ${CERT_PATH} |grep notAfter |cut -d= -f2- |tr -s ' ' |cut -d' ' -f1,2,4)
  DAYS_LEFT=$((($(date -d "$EXPIRY" +%s) - $(date -d "$(date +%F)" +%s))/86400))

  cat $MSG_TEMPLATE \
    | sed -e "s,@DOMAIN@,$1,g" \
          -e "s,@FROM_EMAIL@,$FROM_EMAIL,g" \
          -e "s,@OWNER_EMAIL@,$OWNER_EMAIL,g" \
    | sendmail $OWNER_EMAIL
}

make_mail_cert() {
  # backup/assemble/copy the qmail certificate
  # you can delete the call to this function in hook.sh deploy_cert() if this is not needed

  DOMAIN=$1

  # install the certificate only if $DOMAIN id the mail server domain name
  if [ "$DOMAIN" = "$CERTNAME" ]; then
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
    make_dovecot
  fi
}

make_dovecot() {
  # restart dovecot
  $DOVECOTCTL stop
  sleep 5
  $DOVECOTCTL start
}

make_apache() {
  # restart apache
  echo "Restarting apache"
  $APACHECTL -k graceful
}

startup() {
  echo
  echo ==================================================
  echo
  date
  echo
}
