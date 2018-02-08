#!/bin/bash

echo Content-type: text/plain
echo
echo OK

rm -f tmin.data
killall -USR2 tmin
