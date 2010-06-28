#!/usr/bin/env python
# -*- coding : utf-8 -*-

"""
analyze_shellcode.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2010-06-23 14:25:55'

import os, sys, re
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
                return row[0].split('-')

        return (None, None, None)

def main():
    """TODO
    """
    # try to find the address of:
    # 64 A1 30 00 00 00                       mov     eax, dword ptr fs:loc_30
    # 8B 40 0C                                mov     eax, [eax+0Ch]
    # 8B 70 1C                                mov     esi, [eax+1Ch]
    # AD                                      lodsd
    ea_mov_fs30 = FindBinary( 0, SEARCH_DOWN, "8B ? 0C 8B ? 1C AD" )
    if ea_mov_fs30 == BADADDR:
        print "[-] Can't find address of mov exx, fs:30..."
        return -1

    print "[+] Found fs:30 at: 0x%08X" % ea_mov_fs30

    tmp_ea, ea = PrevHead(ea_mov_fs30, 0), RfirstB0(ea_mov_fs30)   # xrefs to
    while ea == BADADDR or GetMnem(ea) != 'call':
        tmp_ea, ea = PrevHead(tmp_ea, 0), RfirstB0(tmp_ea)

    if GetMnem(RfirstB0(ea)) != 'jmp':
        print "[-] It's not 'jmp', confused at: 0x%08X" % ea
        return -1

    jmp_ea  = RfirstB0(ea)
    call_ea = ea

    print "[+] Found jmp/call pair at: 0x%08X" % jmp_ea

    print "[+] ... try to get hash from call_ea: 0x%08X" % call_ea

    dbf = AskFile( 0, '*.db', 'Please select the hash database' )
    dbh = HashToName(dbf)

    ea  = ea + ItemSize(ea)
    hsh = Dword(ea)
    xstruct, xkey = {}, 0

    # E8 XX XX XX XX                          call loc_xxx
    # 83 B9 B5 78                             dd 78B5B983h
    # E6 17 8F 7B                             dd 7B8F17E6h
    # ... ...
    while hsh != 0:
        ea += 4
        if ea >= MaxEA(): break

        api, fname, offset = dbh.h2n( "%08X" % hsh )
        if api is not None:
            print "[+] %08X: %s, offset: %s, %08X <-> %s" % (ea, fname, offset, hsh, api)
            xstruct[xkey], xkey = api, xkey + 4
        else:
            print "[-] %08X: %08X not found..." % (ea, hsh)
            break

        hsh = Dword(ea)

    # it's not call/dd pair, try bruteforce search
    if len(xstruct.keys()) == 0:
        print "[+] Hash probably exist elsewhere... tring bruteforce way..."
        ea, xkey = MinEA(), 0
        while ea < MaxEA():

            if not isCode( GetFlags(ea) ):
                # try to search Dword(ea)
                hsh = Dword(ea)
                api, fname, offset = dbh.h2n( "%08X" % hsh )
                if api is not None:
                    print "[+] %08X: %s, offset: %s, %08X <-> %s" % (ea, fname, offset, hsh, api)
                    xstruct[xkey], xkey = api, xkey + 4

                ea = NextAddr(ea)
                continue

            # ... ...
            # C7 47 2C 9B 87 8B E5                    mov     dword ptr [edi+2Ch], 0E58B879Bh
            # C7 47 30 ED AF FF B4                    mov     dword ptr [edi+30h], 0B4FFAFEDh
            # E9 E7 03 00 00                          jmp     loc_5DD
            if ( GetMnem(ea) == 'mov' and
                 (GetOpType(ea, 0) == 3 or   # 3 == Base + Index
                  GetOpType(ea, 0) == 4) and # 4 == Base + Index + Displacement
                 GetOpType(ea, 1) == 5 ):    # 5 == Immediate

                opnd = GetOpnd(ea, 0)
                # FIXME what if it's '-'?
                if opnd.find('+') == -1: # first one
                    xkey = 0
                else:
                    rm = re.match( 'dword ptr \[[^+].*\+([^h]+)h?\]', opnd )
                    if rm is not None:
                        xkey = int( rm.group(1), 16 )

                hsh  = GetOperandValue(ea, 1)
                api, fname, offset = dbh.h2n( "%08X" % hsh )
                if api is not None:
                    print "[+] %08X: %s, offset: %s, %08X <-> %s" % (ea, fname, offset, hsh, api)
                    xstruct[xkey] = api
                else:
                    print "[-] %08X: %08X not found..." % (ea, hsh)

            if ( GetMnem(ea) == 'push' and GetOpType(ea, 0) == 5 ): # 5 == Immediate

                hsh = GetOperandValue(ea, 0)
                api, fname, offset = dbh.h2n( "%08X" % hsh )
                if api is not None:
                    print "[+] %08X: %s, offset: %s, %08X <-> %s" % (ea, fname, offset, hsh, api)
                    xstruct[xkey], xkey = api, xkey + 4
                else:
                    print "[-] %08X: %08X not found..." % (ea, hsh)

            ea += ItemSize(ea)  # this must be code

    key_list = xstruct.keys()
    if len(key_list) == 0:
        print "[-] Can't find hash tags...exit"
        return

    str_name = AskStr( '_X', 'Enter a struct name...' )
    str_id   = AddStrucEx( -1, str_name, 0 )
    str_id   = GetStrucIdByName(str_name)

    print "[+] Creating struct[%s] from collected hash, count: %d..." % (str_name, len(key_list))

    for x in xrange(len(key_list)): # FIXME can't sort() ????
        rc = AddStrucMember( str_id, str(xstruct[x*4]), -1, FF_DWRD, -1, 4 )
        if rc !=0: print "[-] ", rc

    print "[+] Try to set offset in struct of call..."

    ea, xkey, delta = MinEA(), 0, 0
    while ea < MaxEA():

        if not isCode( GetFlags(ea) ):
            ea = NextAddr(ea)
            continue

        if ( GetMnem(ea) == 'call' and
             (GetOpType(ea, 0) == 3 or  # 3 == Base + Index
              GetOpType(ea, 0) == 4) ): # 4 == Base + Index + Displacement

            opnd = GetOpnd(ea, 0)

            if opnd.find('-') != -1: # need delta

                OpSign(ea, 0)   # convert

                if delta == 0:                   # only set once
                    delta = GetStrucSize(str_id) # FIXME
                    print "[+] Operand may need a delta, set as %X..." % delta

                xkey = delta - (1 + 0xff - (0xff&GetOperandValue(ea, 0)))

            elif opnd.find('+') != -1:

                mr = re.match( 'dword ptr \[[^+].*\+([^h]+)h?\]', opnd )
                if mr is not None:
                    xkey = int( mr.group(1), 16 )

            else:

                xkey = 0

            try:
                if xstruct[xkey] is not None:
                    print "[+] Convert %08X call off <-> offset in structure: %s" % (ea, xstruct[xkey])
                    OpStroffEx(ea, 0, str_id, delta)
                else:
                    print "[-] %08X: Can't find proper struct offset, weird...%s" % (ea, opnd)
            except Exception, e:
                print "[-] %08X: shit happen... %08X, %s" % (ea, xkey, opnd)

        ea += ItemSize(ea)      # this must be code

    print "[+] Done..."
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
