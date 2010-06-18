#!/usr/bin/env python
# -*- coding : utf-8 -*-
# create_str_via_hash.py
# Binjo @ 2009-04-05 21:47:23
#-------------------------------------------------------------------------------
from idc import *

def get_name_via_hash(arr, hsh):
    """TODO
    """
    for l in arr[1:]:
        h, n = l.strip('\n').split(',')
        if hsh == int(h, 16): return n
    return ''

def main():
    """TODO
    """
    n  = AskStr( '_X', 'Enter a struct name' )
    id = AddStrucEx( -1, n, 0 )
    id = GetStrucIdByName(n)
    ea = here()

    f = AskFile( 0, '*.txt', 'hash to name' )
    fh = open(f, 'r')
    c = fh.readlines()
    fh.close()

    m = AskLong( 0, "Input Count Number or Ignore..." )

    MakeDword(ea)
    h = Dword(ea)
    off = 0
    while h != 0:
        if m != 0 and m != -1:
            if ( off + 4 ) / 4 > m: break
        ea += 4
        if ea >= MaxEA(): break
        n = get_name_via_hash( c, h )
        if n != '':
            print '%08X, %s' % (h, n)
            rc = AddStrucMember( id, n.strip(' '), off, FF_DWRD, -1, 4 )
            if rc != 0: print '[-] ', rc
        else:
            print '%08X not found...' % h
        MakeDword(ea)
        h = Dword(ea)
        off += 4
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
