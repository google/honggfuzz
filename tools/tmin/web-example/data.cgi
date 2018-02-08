#!/bin/bash

echo Content-Type: text/html
echo

while [ ! -s tmin.data ]; do
  usleep 10000
done 2>/dev/null

cat tmin.data
