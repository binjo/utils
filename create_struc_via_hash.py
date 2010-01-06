#!/usr/bin/env python
# -*- coding : utf-8 -*-
# create_struc_via_hash.py
# Binjo @ 2009-04-08 11:05
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

    idx = AskLong( 0, "Input Operand Index..." )
    m = AskLong( 0, "Input Count Number or Ignore..." )

    h = GetOperandValue(ea, idx)
    off = 0
    i = 0
    while h != -1:
        i += 1
        if m != 0 and m != -1:
            if i > m: break
        ea += ItemSize(ea)
        n = get_name_via_hash( c, h )
        if n != '':
            print '%08X, %s' % (h, n)
            rc = AddStrucMember( id, n.strip(' '), off, FF_DWRD, -1, 4 )
            if rc != 0: print '[-] ', rc
        else:
            print '%08X not found...' % h
        h = GetOperandValue(ea, idx)
        off += 4
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
