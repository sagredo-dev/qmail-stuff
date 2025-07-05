#!/bin/bash
#
# https://dovecot.org/pipermail/dovecot/2022-May/124711.html
#
# Rescan indexes after a Solr upgrade

PROT=http
USER=dovecot
 PWD=xxxxx
HOST=localhost
PORT=8983

# Use the url of the solr connection in your local.conf
DOVECOT_SOLR_URL_BASE="${PROT}://${USER}:${PWD}@${HOST}:${PORT}/solr/dovecot"
# if you haven't secured solr with user/pwd use this one
#DOVECOT_SOLR_URL_BASE="${PROT}://${HOST}:${PORT}/solr/dovecot"

######################## DO NOT MODIFY BELOW WITHOUT GOOD REASON

DEL_ALL_QUERY_XML="<delete><query>*:*</query></delete>"
dovecotctl stop
curl \
   "${DOVECOT_SOLR_URL_BASE}/update?commit=true&optimize=true" \
   -H "Content-Type: text/xml" \
   --data-binary "${DEL_ALL_QUERY_XML}"
dovecotctl start
doveadm force-resync -A '*'
doveadm fts rescan -A
doveadm index -A -q '*'
