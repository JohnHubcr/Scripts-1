#!/bin/bash
for name in $(cat dns.txt);do
host $name.checkpoint.com
done
