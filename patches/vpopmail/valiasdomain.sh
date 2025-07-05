#!/bin/bash
#
# v. 2021.02.03
# by Roberto Puzzanghera
# More info here https://notes.sagredo.eu/en/qmail-notes-185/dovecot-vpopmail-auth-driver-removal-241.html
#
# Records/delete the aliasdomains in mysql
# This gets dovecot's sql auth driver working with vpopmail's aliasdomains as well
#
#############################################################################################

# vpopmail config path. default VPOPMAILDIR eventually changed by configure command
VPOPMAILDIR="/home/vpopmail"
VPOPMAIL_MYSQL_CONFIG=$VPOPMAILDIR"/etc/vpopmail.mysql"

# mysql bin path
MYSQL=""
for f in /usr/bin/mysql /usr/mysql/bin/mysql /usr/local/mysql/bin/mysql /usr/local/bin/mysql
do
    if test -x $f
    then
        MYSQL=$f
        break
    fi
done
if [[ $MYSQL == "" ]]; then
	echo "MySQL binary not found. sql-aliasdomain not created."
	echo "If you have MySQL installed edit your $VPOPMAILDIR/bin/valiasdomain file."
	exit 1;
fi

# sed path
SED=""
for f in /usr/bin/sed /usr/sbin/sed /usr/local/bin/sed /usr/local/sbin/sed
do
    if test -x $f
    then
        SED=$f
        break
    fi
done
if [[ $SED == "" ]]; then
        echo "sed binary not found. sql-aliasdomain not created."
        echo "If you have sed installed edit your $VPOPMAILDIR/bin/valiasdomain file."
        exit 1;
fi

# extract mysql params
HOST=$($SED -n "/#/! s/^\(.*\)|.*|.*|.*|.*/\1/p" $VPOPMAIL_MYSQL_CONFIG)
PORT=$($SED -n "/#/! s/^.*|\(.*\)|.*|.*|.*/\1/p" $VPOPMAIL_MYSQL_CONFIG)
USER=$($SED -n "/#/! s/^.*|.*|\(.*\)|.*|.*/\1/p" $VPOPMAIL_MYSQL_CONFIG)
 PWD=$($SED -n "/#/! s/^.*|.*|.*|\(.*\)|.*/\1/p" $VPOPMAIL_MYSQL_CONFIG)
  DB=$($SED -n "/#/! s/^.*|.*|.*|.*|\(.*\)/\1/p" $VPOPMAIL_MYSQL_CONFIG)

######################################################################################

# connect to mysql and do the query
function exec_query() {
        $MYSQL -h $HOST -P $PORT -u $USER -p$PWD -N -A < /tmp/query.sql
}

# create the table if not exists
function create_table() {
        # Output the query to a file that we want to run
        cat << EOF > /tmp/query.sql;
	USE $DB;
	CREATE TABLE IF NOT EXISTS aliasdomains (
	alias varchar(100) NOT NULL,
	domain varchar(100) NOT NULL,
	PRIMARY KEY (alias)
	) ENGINE=InnoDB DEFAULT CHARSET=latin1;
EOF
        # Execute the query
        exec_query
}

# create the alias
function create() {
	# create table if not exist
	create_table
	# Output the query to a file that we want to run
	cat << EOF > /tmp/query.sql;
	USE $DB;
	INSERT IGNORE INTO aliasdomains (domain,alias) VALUES ("$1","$2");
EOF
	# Execute the query
	exec_query
}

# delete the alias
function delete() {
        # create table if not exist
        create_table
        # Output the query to a file that we want to run
        cat << EOF > /tmp/query.sql;
        USE $DB;
        DELETE FROM aliasdomains WHERE alias="$1";
EOF
        # Execute the query
        exec_query
}

# delete all aliases related to a domain
function force_delete() {
        # create table if not exist
        create_table
        # Output the query to a file that we want to run
        cat << EOF > /tmp/query.sql;
        USE $DB;
        DELETE FROM aliasdomains WHERE domain="$1";
EOF
        # Execute the query
        exec_query
}


if [ "$2" = 'delete' ]; then

    # Delete mysql record
    delete $1

elif [ "$2" = 'force' ]; then

    # Delete mysql records
    force_delete $1

elif [ "$2" != '' ]; then

    # Create mysql record
    create $1 $2

elif [ "$1" = '' ] || [ "$1" = 'help' ]; then

    # Usage
    echo
    echo "Usage"
    echo
    echo "Creating an aliasdomain:"
    echo "$0 <real_domain> <alias_domain>"
    echo
    echo "Deleting an aliasdomain:"
    echo "$0 <alias_domain> delete"
    echo
    echo "Deleting all aliases related to a domain:"
    echo "$0 <domain> force"
    echo
fi

exit 0
