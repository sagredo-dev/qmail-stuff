#!/bin/bash
#
# Author: Costel Balta
# Slightly modified by Roberto Puzzanghera
#

# MySQL details
HOST="localhost";
USER="vpopmail";
PWD="your-pwd";
MYSQL="/usr/local/mysql/bin/mysql";
# dovecot details
DOVEADM="/usr/local/dovecot/bin/doveadm";

# Output sql to a file that we want to run
echo "USE vpopmail; select concat(pw_name,'@',pw_domain) as username from vpopmail;" > /tmp/query.sql;

# Run the query and get the results
results=`$MYSQL -h $HOST -u $USER -p$PWD -N < /tmp/query.sql`;

# Loop through each row
for row in $results
        do
        echo "Purging $row Trash and Junk mailbox..."
        # Purge expired Trash
        $DOVEADM -v expunge mailbox Trash -u $row savedbefore 90d
        # Purge expired Junk
        $DOVEADM -v expunge mailbox Junk  -u $row savedbefore 60d
done
