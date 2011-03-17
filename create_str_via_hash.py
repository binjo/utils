#!/usr/bin/env python
# -*- coding: utf-8 -*-
# create_str_via_hash.py
# Binjo @ 2009-04-05 21:47:23
#-------------------------------------------------------------------------------
import sqlite3
from idc import *

class HashToName(object):
    """wrapper of hash <-> name
    """

    def __init__(self, dbf):
        """

        Arguments:
        - `dbf`:
        """
        self._dbf  = dbf
        self._db   = None
        self._conn = None

        if os.path.isfile(dbf):
            self._db = sqlite3.connect(dbf)
            self._conn = self._db.cursor()

    def h2n(self, hsh):
        """hash <-> name

        Arguments:
        - `self`:
        - `hsh`:
        """
        if hsh != '' and self._conn is not None:
            self._conn.execute("select api_name from hashes where api_hash=?",
                               (hsh,))
            row = self._conn.fetchone()
            if row is not None:
                return str(row[0]).split('-')

        return (None, None, None)

def main():
    """TODO
    """
    n  = AskStr( '_X', 'Enter a struct name' )
    id = AddStrucEx( -1, n, 0 )
    id = GetStrucIdByName(n)
    ea = here()

    dbf = AskFile( 0, '*.db', 'Please select the hash database' )
    dbh = HashToName(dbf)

    m = AskLong( 0, "Input Count Number or Ignore..." )

    MakeDword(ea)
    h = Dword(ea)
    off = 0
    while h != 0:
        if m != 0 and m != -1:
            if ( off + 4 ) / 4 > m: break
        ea += 4
        if ea >= MaxEA(): break
        n, fname, offset = dbh.h2n( "%08X" % h )
        if n is not None:
            print "[+] %08X: %s, offset: %s, %08X <-> %s" % (ea, fname, offset, h, n)
            rc = AddStrucMember( id, str(n), off, FF_DWRD, 0xffffffff, 4 )
            if rc != 0: print '[-] ', rc
        else:
            print '%08X: %08X not found...' % (ea, h)
        MakeDword(ea)
        h = Dword(ea)
        off += 4
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
