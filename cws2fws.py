#!/usr/bin/env python
# -*- coding: utf-8 -*-
# cws2fws.py
# Binjo @ 2009-09-05 11:13:08
#-------------------------------------------------------------------------------
from __future__ import with_statement
from zlib       import decompress
import sys

def main():
    """TODO
    """
    with open(sys.argv[1], 'rb') as fh:
        c = fh.read()

    if c[:3] != 'CWS':
        exit( '[-] File is not compressed...' )

    ver = c[3]

    nc  = decompress( c[8:] )

    with open(sys.argv[2], 'wb') as fh:
        fh.write( 'FWS' + ver + c[4:8] + nc )
        print "[+] Done, check out %s..." % sys.argv[2]
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
