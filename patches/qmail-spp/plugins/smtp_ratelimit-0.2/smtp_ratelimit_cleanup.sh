#!/bin/bash

cd ~qmaild
CONFIG_FILE="control/smtp_ratelimit"
if [ ! -e ${CONFIG_FILE} ]; then
  echo "Config file doesn't exist."
  exit 1
fi

# read configuration
. ${CONFIG_FILE}
mysql_default_file=$(echo ${mysql_default_file} | tr -d '\r')
refill_nr=$(( max_tokens / refill_tokens ))
[[ $(( max_tokens % refill_tokens )) -gt 0 ]] && refill_nr=$((refill_nr+1))
expires=$(( refill_nr * refill_time ))

mysql --defaults-file=${mysql_default_file} \
  -e 'DELETE FROM `smtp_ratelimit` WHERE `last_refill` <= NOW() - INTERVAL '${expires}' SECOND'
