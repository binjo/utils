#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
extract_fws_from_pdf.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2009-08-28 11:16:26'

import sys, struct
def main():
    """TODO
    """
    fh = open( sys.argv[1], 'rb' )
    xx = fh.read()
    fh.close

    pos = 0
    i = 0
    while True:
        pos = xx.find( 'FWS', pos+1 )
        if pos == -1: break
        nel = struct.unpack( 'L', xx[pos+4:pos+8] )[0]
        fh = open( "x%d.swf_" % i, 'wb' )
        fh.write( xx[pos:pos+nel] )
        fh.close()
        i += 1
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
