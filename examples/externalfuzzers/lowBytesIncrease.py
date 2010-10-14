#!/usr/bin/env python

import os, sys, mmap
from random import randint

CAP = 0x20
RANDADDMAX = 0x20

with open(sys.argv[1], "r+b") as f:
  map = mmap.mmap(f.fileno(), 0)
  for index, char in enumerate(map):
    if ord(char) < CAP:
      map[index] = chr(ord(char) + randint(0, RANDADDMAX))
  map.close()
