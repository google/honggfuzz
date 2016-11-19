#!/bin/sh
echo "running $@"
cat $1|zzuf > ./tmp
mv ./tmp $1
