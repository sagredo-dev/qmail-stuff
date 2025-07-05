#!/bin/bash
#
# Author: Costel Balta
# Slightly modified by Roberto Puzzanghera
#
 
# MySQL details
HOST="mysql-server-IP";
USER="vpopmail";
PWD="vpopmailpasswod";
 
# Output sql to a file that we want to run
echo "USE vpopmail; select concat(pw_name,'@',pw_domain) as username from vpopmail;" > /tmp/query.sql;
 
# Run the query and get the results
results=`mysql -h $HOST -u $USER -p$PWD -N < /tmp/query.sql`;
 
# Loop through each row
for row in $results
        do
        echo "Purging $row Trash and Junk mailbox..."
        # Purge expired Trash
        /usr/local/dovecot/bin/doveadm -v expunge mailbox Trash -u $row savedbefore 90d
        # Purge expired Junk
        /usr/local/dovecot/bin/doveadm -v expunge mailbox Junk  -u $row savedbefore 60d
done
