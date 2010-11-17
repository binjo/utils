#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ida_revert_struct.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2009-07-06 11:01:12'

from idc import *

def main():
    """TODO
    """
    m = AskStr( '_X', 'Enter the source struct name to reverse' )
    n = AskStr( '_Y', 'Enter the new struct name...' )

    i = GetStrucIdByName(m)
    j = AddStrucEx( -1, n, 0 )
    j = GetStrucIdByName(n)

    a = []
    off = GetFirstMember(i)
    num = GetMemberQty(i)
    for x in xrange(num):
        a.append( GetMemberName(i, off) )
        off = GetStrucNextOff( i, off )

    print a

    ffo = 0
    for x in a[::-1]:
        rc = AddStrucMember( j, x, ffo, FF_DWRD, -1, 4 )
        if rc != 0: print '[-] ', rc
        ffo += 4
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
