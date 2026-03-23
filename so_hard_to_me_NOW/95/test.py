#!/usr/bin/env python3
import sys
import subprocess

if len(sys.argv) < 3:
    print('Usage: %s dreamy.bmp 2' % sys.argv[0])
    sys.exit(1)

with open(sys.argv[1], 'rb') as f:
    bmp = f.read()
scale = int(sys.argv[2])

hdr = b'%d %d\n' % (scale, len(bmp))
subprocess.run(['./unibitmap'], input=hdr+bmp)
