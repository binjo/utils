#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
extract_swf_from_msole2.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2011-04-15 09:31:30'

import os, sys
import struct as s

def main():
    """TODO
    """
    if len( sys.argv ) != 3:
        sys.exit( "%s doc xxx.swf" % sys.argv[0] )

    ctn = open( sys.argv[1], 'rb' ).read()

    pos = ctn.find( "FWS" )
    if pos == -1:
        pos = ctn.find( "CWS" )
        if pos == -1:
            sys.exit( "%s don't embeds swf..." % sys.argv[1] )

    l = s.unpack( "L", ctn[pos-4:pos] )[0]
    f = open( sys.argv[2], 'wb' )
    f.write( ctn[pos:pos+l] )
    print "done..."
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
