#!/bin/sh
#
# https://certbot.eff.org/docs/
# http://www.slackbuilds.org/repository/14.2/system/letsencrypt/
# https://community.letsencrypt.org/t/tls-sni-challenges-disabled-for-most-new-issuance/50316

CERTBOT=/usr/bin/certbot
DOMAIN=mydomain.tld

$CERTBOT certonly \
        --webroot \
        --webroot-path /path/to/webroot \
        --preferred-challenges http-01 \
	--key-type rsa \
        -d ${DOMAIN}
        --email myemail@${DOMAIN} \
        --renew-by-default \
        --agree-tos \
        --text

# qmail cert
if [ ! -d "/var/qmail/control/certs_backup" ]; then
        mkdir -p /var/qmail/control/certs_backup
fi
cp -p /var/qmail/control/*.pem /var/qmail/control/certs_backup/
cat /etc/letsencrypt/live/${DOMAIN}/privkey.pem /etc/letsencrypt/live/${DOMAIN}/fullchain.pem > /var/qmail/control/servercert.pem
/usr/local/bin/qmailctl restart

# dovecot cert (you have to set the path inside 10-ssl.conf accordingly)
/usr/local/bin/dovecotctl restart
