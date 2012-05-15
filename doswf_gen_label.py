#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
doswf_gen_label.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2012-05-07 16:59:13'

import os, sys, re

def main():
    """TODO
    """
    if len(sys.argv) != 3:
        sys.exit( "usage: %s doswfed.as doswf_.as" % sys.argv[0] )

    ctn = open( sys.argv[1], 'rb' ).read()
    fh  = open( sys.argv[2], 'wb' )

    i = 0
    while i < len(ctn):

        x = ord(ctn[i])
        if ( x >= 0xc0 and x < 0xf2 ):
            tag = ''.join( [f+k for f, k in
                            zip( [x for x in hex( ord(ctn[i]) ).replace('0x', '') + hex( ord( ctn[i+1] ) ).replace('0x', '') ],
                                 ['\x00', '\x00', '\x00', '\x00'] )  ] )
            fh.write( '_\x00d\x00o\x00s\x00w\x00_\x00' + tag )
            i += 2
        else:
            fh.write( ctn[i] )
            i += 1

#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
