#!/bin/sh
echo "running $@"
touch ./tmp
radamsa $1 > ./tmp
mv ./tmp $1
