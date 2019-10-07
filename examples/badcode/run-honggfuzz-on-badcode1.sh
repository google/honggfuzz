#!/bin/sh
../../honggfuzz -n1 -u -i inputfiles -- targets/badcode1 ___FILE___
