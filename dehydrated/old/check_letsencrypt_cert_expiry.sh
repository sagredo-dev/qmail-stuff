#!/bin/sh
#
# ---------------------------------------------------------------------------
#
# Check Let's Encrypt SSL certificate expiration date.
# Send reminder emails starting 15 days (configurable) before expiry.
# Author: Eric Hameleers <alien@slackware.com>, 2025
#
# Modified by R. Puzzanghera https://www.sagredo.eu to get qmail-inject compat.
#
# Schedule this script for instance via root's cron to run once per week:
# 45 2 * * wed      /etc/dehydrated/check_letsencrypt_cert_expiry.sh
#
# ---------------------------------------------------------------------------

# Configuration for the script (email addresses and time to warn):
CONFFILE="$(dirname $0)/$(basename $0 .sh).conf"
[ -f ${CONFFILE} ] && . ${CONFFILE}

# The message template which will be used to draft the email:
MSGTEMPLATE="$(dirname $0)/$(basename $0 .sh).tpl"

# When to start sending warning emails:
WARNDAYS=${WARNDAYS:-"15"}

# From and to email addresses:
FROMEMAIL=${FROMEMAIL:-"UNDEFINED"}
OWNEREMAIL=${OWNEREMAIL:-"UNDEFINED"}

if [ ! -f "$MSGTEMPLATE" ]; then
  echo "** Can not find mail message template '$MSGTEMPLATE'!"
  echo "** Aborting..."
  exit 1
fi

# Cycle through the domain certificates we manage via dehydrated:
for DOMAIN in /etc/dehydrated/certs/*/cert.pem ; do
  EXPIRY=$(openssl x509 -noout -dates -in ${DOMAIN} |grep notAfter |cut -d= -f2- |tr -s ' ' |cut -d' ' -f1,2,4)
  DOMAIN=$(echo $DOMAIN |cut -d/ -f5)
  SUBDOMAINS=$(cat /etc/dehydrated/domains.txt |grep ^$DOMAIN |sed -e 's, ,\\n,g')
  NRSUBS=$(cat /etc/dehydrated/domains.txt |grep ^$DOMAIN |tr ' ' '\n' |wc -l)
  if [ $NRSUBS -gt 1 ]; then
    EXTRAWARN="(and $((NRSUBS-1)) more)"
  else
    EXTRAWARN=""
  fi
  DAYSLEFT=$((($(date -d "$EXPIRY" +%s) - $(date -d "$(date +%F)" +%s))/86400))
  if [ $DAYSLEFT -le $WARNDAYS ]; then
    # Inform owner email about impending certificate expiry:
    cat $MSGTEMPLATE \
      | sed -e "s,@DAYSLEFT@,$DAYSLEFT,g" \
            -e "s,@DOMAIN@,$DOMAIN,g" \
            -e "s,@EXPIRY@,$EXPIRY,g" \
            -e "s,@FROMEMAIL@,$FROMEMAIL,g" \
            -e "s,@OWNEREMAIL@,$OWNEREMAIL,g" \
            -e "s,@EXTRAWARN@,$EXTRAWARN,g" \
            -e "s,@SUBDOMAINS@,$SUBDOMAINS,m" \
      | qmail-inject
  fi
done
