#!/bin/bash
#
# tx Bai Borko https://notes.sagredo.eu/en/qmail-notes-185/greylisting-for-qmail-254.html#comment3036

SMTPDLOG='/var/log/qmail/smtpd/current'
BACKUPDIR='/var/log/qmail/backup'
JGRAYDIR='/var/qmail/jgreylist'
FIELD=`echo ${JGRAYDIR}|tr -dc '/'|wc -c`
FIELD=$((FIELD+3))
TMPLIST="$(mktemp)"
TMPLIST_TMP="$(mktemp)"
DAYS=30
INTNET='192.168.0'

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/var/qmail/bin

grlist() {
  grep "result=accepted code=250" $1|tai64nlocal| cut -d ' ' -f1-2,20|tr '=' ' '|grep -v ${INTNET}|awk -F '.' '{print $1" "$2"."$3"."$4}'|cut -d ' ' -f1,2,5 >>$TMPLIST
}

for i in `find $BACKUPDIR -name "qmail-smtpd.*" -mtime -${DAYS}`; do 
  grlist $i
done

grlist $SMTPDLOG

cat $TMPLIST |sort -k 3 -u > $TMPLIST_TMP
mv $TMPLIST_TMP $TMPLIST
umask 077

while read line; do
  MTIME=`echo "$line"|tr -d '-'|awk -F: '{print $1$2"."$3}'|awk '{print $1$2}'`
  TMPSTR=''
  for NUM in `echo "$line"|cut -d ' ' -f3|tr '.' ' '`;do
    if [[ ${#NUM} -eq 1 ]] ; then
    NUM="00${NUM}"
  elif [[ ${#NUM} -eq 2 ]] ; then
    NUM="0${NUM}"
  fi
  TMPSTR=${TMPSTR}${NUM}/
done

FILE=`echo ${JGRAYDIR}.tmp/${TMPSTR} |rev |cut -c2- |rev`
DIR=`echo ${FILE} |cut -d / -f -${FIELD} -` 
#Make dir if not exist
if [ ! -d "$DIR" ]; then
  mkdir -p "$DIR"
fi

touch -a -m -t $MTIME $FILE
done < $TMPLIST
chown -R vpopmail:vchkpw "${JGRAYDIR}.tmp"
mv ${JGRAYDIR} "${JGRAYDIR}.4del" 
mv "${JGRAYDIR}.tmp" ${JGRAYDIR}
rm -fr "${JGRAYDIR}.4del" $TMPLIST
