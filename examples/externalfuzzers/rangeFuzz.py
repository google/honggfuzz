#!/usr/bin/env python

import mmap
import os
from random import randint
import sys

RANGE_START = 0x1b30
RANGE_END   = 0x1b50
MIN_BYTES_TO_FLIP = 1
MAX_BYTES_TO_FLIP = 5

with open(sys.argv[1], "r+b") as f:
  mapped = mmap.mmap(f.fileno(), 0)

  bytes_to_flip = randint(MIN_BYTES_TO_FLIP, MAX_BYTES_TO_FLIP)
  bytes_flipped = 0

  while bytes_flipped < bytes_to_flip:
    byte_pos = randint(RANGE_START, RANGE_END)
    byte_new = chr(randint(0, 255))
    mapped[byte_pos] = byte_new
    bytes_flipped += 1

  mapped.close()
