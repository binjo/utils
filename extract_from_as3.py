#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
extract_from_as3.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2014-02-11 16:34:50'

import os, sys
from winappdbg import System

def main():
    """TODO
    """
    print "...as script dumper for as3s.exe..."

    if len(sys.argv) != 2:
        print "usage: %s pid swf" % sys.argv[0]
        return

    try:
        s = System()
        s.request_debug_privileges()
        s.scan()
        p = s.find_processes_by_filename("as3s.exe")[0][0]
    except Exception, e:
        print "[-] oops..." % str(e)
        return

    i = 0
    for addr in p.search( 'package {' ): # FIXME
        print "[+] found script  @ 0x%08x" % addr
        size = p.read_int( addr - 4 )
        print "[+] script length = 0x%08x" % size
        ctn  = p.read_string( addr, size )
        with open( str(i) + sys.argv[1], 'wb' ) as fh:
            fh.write(ctn)
        print "[+] done, check out ... %s" % sys.argv[1]
        i += 1

#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
