#!/usr/bin/env python
# -*- coding : utf-8 -*-

"""
calc_api_name_hash.py

TODO
"""
__author__      = 'Binjo'
__version__     = '0.3'
__date__        = '2008-10-28 15:25:46'
__description__ = "Calculate api names' hash or Search name via hash."

import os, sys
import pefile
import optparse
import sqlite3

FILEZ       = {
    'kernel32'  :   'c:/windows/system32/kernel32.dll',
    'ntdll'     :   'c:/windows/system32/ntdll.dll',
    'shell32'   :   'c:/windows/system32/shell32.dll',
    'user32'    :   'c:/windows/system32/user32.dll',
    'urlmon'    :   'c:/windows/system32/urlmon.dll',
    }

db = sqlite3.connect( 'api_name_hash.db' )
db.isolation_level = None       # auto commit
cr = db.cursor()
if ( (not os.path.isfile('api_name_hash.db')) or
     os.path.getsize('api_name_hash.db') == 0 ):
    # api_hash : XXXXXXXX
    # api_name : name-file-offset
    cr.execute("""
        create table hashes (api_hash text, api_name text)""")

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
    opt = optparse.OptionParser( usage='usage: %prog [options]\n' + __description__, version='%prog ' + __version__)
    opt.add_option( '-s', '--search', help='hash string to search' )
    opt.add_option( '-o', '--offset', help='offset for the calculation' )
    opt.add_option( '-f', '--file',   help='file name' )

    (opts, args) = opt.parse_args()

    if len(args) != 0:
        opt.print_help()
        print '  -f is as follows:'
        for k, v in FILEZ.iteritems():
            print '    %s -> %s' % ( k, v )
        exit(-1)

    keyname  = opts.file
    searchee = opts.search
    offset   = opts.offset

    # for search
    if searchee is not None:
        cr.execute("select api_name from hashes where api_hash=?",
                   ("%08X" % int( searchee, 16 ), ))
        print "%s, %08X" % (cr.fetchone()[0], int( searchee, 16 ))
        return

    # insert table
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
            print '%08X, %s' % ( v, n )
            if v == -1: continue
            cr.execute("""
                insert into hashes
                values ( ?, ? )""", ("%08X" % v, "%s-%s-%s" % (n, keyname, offset)) )
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
