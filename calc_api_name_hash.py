#!/usr/bin/env python
# -*- coding : utf-8 -*-

"""
calc_api_name_hash.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.2'
__date__    = '2008-10-28 15:25:46'

import sys
import pefile

FILEZ       = {
    'kernel32'  :   'c:/windows/system32/kernel32.dll',
    'ntdll'     :   'c:/windows/system32/ntdll.dll',
    'shell32'   :   'c:/windows/system32/shell32.dll',
    'user32'    :   'c:/windows/system32/user32.dll',
    'urlmon'    :   'c:/windows/system32/urlmon.dll',
    }

def calc_hash(src, off):
    """
                push    esi
                xor     esi, esi
loc_108A:
                movsx   edx, byte ptr [eax]
                cmp     dh, dl
                jz      short loc_1099
                ror     esi, 0Dh
                add     esi, edx
                inc     eax
                jmp     short loc_108A

    """
    if src is None: return( -1, src)

    h = 0
    for x in src.rstrip('\n'):
        h  = (h >> int(off)) ^ (0xFFFFFFFF & (h << (32 - int(off))))
        h += ord(x)
    return (h, src)

def main():
    """TODO
    """
    if len(sys.argv) < 5:
        print '%s -[s|f] src -o off' % sys.argv[0]
        print '  -f is as follows:'
        for k, v in FILEZ.iteritems():
            print '    %s -> %s' % ( k, v )
        exit(-1)

    keyname  = None
    searchee = None
    for i in xrange(len(sys.argv)):
        if sys.argv[i] == '-f':
            keyname  = sys.argv[i+1]
        elif sys.argv[i] == '-s':
            searchee = int(sys.argv[i+1], 16)
        elif sys.argv[i] == '-o':
            offset   = sys.argv[i+1]

    print 'offset %s, %s' % ( offset, keyname )

    def filter_rule(x):
        """

        Arguments:
        - `x`:
        """
        if keyname is not None:
            return x == keyname
        else:
            return True

    files = filter( filter_rule, FILEZ.keys() )

    for f in files:
        dll = FILEZ.get( f, '' )
        if dll != '':
            pe = pefile.PE(dll)

        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            v, n = calc_hash( s.name, offset )
            if searchee is not None:
                if v == searchee:
                    print '%08X, %s' % (v, n)
                    break
            else:
                print '%08X, %s' % ( v, n )
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
