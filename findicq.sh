#!/bin/bash
for hostname in $(cat icq-serv.txt);do
host $hostname | grep "has address"
done
