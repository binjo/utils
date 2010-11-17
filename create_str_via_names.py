#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
create_str_via_names.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2009-11-06 11:59:07'

import os, sys

def main():
    """TODO
    """
    n  = AskStr( '_X', 'Enter a struct name' )
    id = AddStrucEx( -1, n, 0 )
    id = GetStrucIdByName(n)

    f = AskFile( 0, '*.txt', 'name lists file' )
    fh = open(f, 'r')
    c = fh.readlines()
    fh.close()

    for i in xrange(0, len(c)):
        rc = AddStrucMember( id, c[i].strip('\n'), i*4, FF_DWRD, -1, 4 )
        if rc != 0: print '[-] ', rc
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
