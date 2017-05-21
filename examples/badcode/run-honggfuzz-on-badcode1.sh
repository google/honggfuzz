#!/bin/sh
../../honggfuzz -n1 -u -f inputfiles -- targets/badcode1 ___FILE___
