#!/bin/sh
../../honggfuzz -n1 -u -f inputfiles -c ../externalfuzzers/lowBytesIncrease.py -- targets/badcode1 ___FILE___
