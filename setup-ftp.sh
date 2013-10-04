#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
echo "[*] Setting up FTP user offsec\n"
pure-pw useradd offsec -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
echo "[*] Setting home directory in /ftphome/\n"
mkdir /ftphome
chown -R ftpuser:ftpgroup /ftphome/
echo "[*] Starting FTP server\n"
/etc/init.d/pure-ftpd restart
