#!/bin/sh
echo "running $@"
cat $1 | sed -e s/o/0/g > /tmp/f
mv /tmp/f $1
