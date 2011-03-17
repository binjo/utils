#!/usr/bin/env python
# -*- coding: utf-8 -*-
# create_struc_via_hash.py
# Binjo @ 2009-04-08 11:05
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

    idx = AskLong( 0, "Input Operand Index..." )
    m = AskLong( 0, "Input Count Number or Ignore..." )

    h = GetOperandValue(ea, idx)
    i = 0
    while h != -1:
        if m != 0 and m != -1:
            if i > m: break
        ea += ItemSize(ea)
        n, fname, offset = dbh.h2n( "%08X" % h )
        if n is not None:
            print "[+] %08X: %s, offset: %s, %08X <-> %s" % (ea, fname, offset, h, n)
            rc = AddStrucMember( id, n, i * 4, FF_DWRD, 0xffffffff, 4 )
            if rc != 0: print '[-] ', rc
            i += 1              # found one api name
        else:
            print '[-] %08X: %08X not found...' % (ea, h)
        h = GetOperandValue(ea, idx)
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
