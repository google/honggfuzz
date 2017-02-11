#!/bin/sh
../honggfuzz -n1 -u -f inputfiles/badcode1.txt -c externalfuzzers/lowBytesIncrease.py -- targets/badcode1 ___FILE___
