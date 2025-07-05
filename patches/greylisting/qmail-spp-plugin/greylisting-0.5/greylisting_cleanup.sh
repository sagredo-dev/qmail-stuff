#!/bin/bash

cd /var/qmail
CONFIG_FILE="control/greylisting"
if [ ! -e ${CONFIG_FILE} ]; then
  echo "Config file doesn't exist."
  exit 1
fi

# read configuration
. ${CONFIG_FILE}
mysql_default_file=$(echo ${mysql_default_file} | tr -d '\r')

mysql --defaults-file=${mysql_default_file} \
 -e 'DELETE FROM `greylisting_data` WHERE `record_expires` <= UTC_TIMESTAMP()'
