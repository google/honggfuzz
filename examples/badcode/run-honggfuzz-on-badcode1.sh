#!/bin/sh
../honggfuzz -n1 -u -f inputfiles/badcode1.txt -- targets/badcode1 ___FILE___
