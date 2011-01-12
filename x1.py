#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
x1.py

md5 : 70dce90db0acd9bee0e52e71799a4a14
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2011-01-10 16:16:12'

import os, sys
import struct as s

def main():
    """TODO
    """
    ctn = open( sys.argv[1], 'rb' ).read()

    pos = ctn.find( "XXXXYYYY" )

    if pos == -1: exit( "XXXXYYYY not found..." )

    sop = ctn.find( "YYYYXXXX", pos+8 )

    if sop == -1: exit( "YYYYXXXX not found..." )

    i = sop - pos - 8

    f = open( sys.argv[2], 'wb' )
    f.write( "\x4d\x5a\x90\x00" )
    for x in ctn[pos+8:sop]:
        f.write( s.pack('B', s.unpack('B', x)[0] ^ (0xff&i)) )
        i -= 1

    f.close()
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
