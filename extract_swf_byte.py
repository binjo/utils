#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import with_statement
"""
extract_swf_byte.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2009-09-04 12:05:07'
import struct as s
import sys

def main():
    """TODO
    """
    with open( sys.argv[1], 'rb' ) as fh:
        xx = fh.read()

    pos, i = 0, 0
    while True:
        pos = xx.find( '465753', pos+1 )               # 'FWS'
        if pos == -1: break

        with open( str(i) + sys.argv[2], 'wb' ) as fh:
            nel = int( xx[pos+14] +     \
                           xx[pos+15] + \
                           xx[pos+12] + \
                           xx[pos+13] + \
                           xx[pos+10] + \
                           xx[pos+11] + \
                           xx[pos+8] + \
                           xx[pos+9], 16 )
            for x in xrange( pos, pos+nel*2, 2 ):
                fh.write( s.pack('B',int(xx[x] + xx[x+1], 16)) )
        i += 1
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
