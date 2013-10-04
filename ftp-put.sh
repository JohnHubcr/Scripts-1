#!/bin/sh
HOST='192.168.12.32'
USER='offsec'
PASSWD='Bravo141'
FILE='proof.txt'

ftp -n $HOST << BLAH
quote USER $USER
quote PASS $PASSWD
bin
put $FILE
quit
END_SCRIPT
exit 0
