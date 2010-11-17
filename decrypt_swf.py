#!/usr/bin/env python
# -*- coding: utf-8 -*-
# decrypt_swf.py
# Binjo @ 2009-09-05 13:55:20
#-------------------------------------------------------------------------------
from __future__ import with_statement
import sys, struct

"""
     method <q>[public]::String <q>[public]::repl_num=(<q>[public]::String)(1 params, 0 optional)
    [stack:2 locals:2 scope:1-1 flags:] slot:0
    {
        00000) + 0:0 getlocal_1
        00001) + 1:0 pushstring "C"
        00002) + 2:0 ifne ->5
        00003) + 0:0 pushstring "0"
        00004) + 1:0 returnvalue
        00005) + 0:0 getlocal_1
        00006) + 1:0 pushstring "3"
        00007) + 2:0 ifne ->10
        00008) + 0:0 pushstring "1"
        00009) + 1:0 returnvalue
        00010) + 0:0 getlocal_1
        00011) + 1:0 pushstring "D"
        00012) + 2:0 ifne ->15
        00013) + 0:0 pushstring "2"
        00014) + 1:0 returnvalue
        00015) + 0:0 getlocal_1
        00016) + 1:0 pushstring "0"
        00017) + 2:0 ifne ->20
        00018) + 0:0 pushstring "3"
        00019) + 1:0 returnvalue
        00020) + 0:0 getlocal_1
        00021) + 1:0 pushstring "2"
        00022) + 2:0 ifne ->25
        00023) + 0:0 pushstring "4"
        00024) + 1:0 returnvalue
        00025) + 0:0 getlocal_1
        00026) + 1:0 pushstring "1"
        00027) + 2:0 ifne ->30
        00028) + 0:0 pushstring "5"
        00029) + 1:0 returnvalue
        00030) + 0:0 getlocal_1
        00031) + 1:0 pushstring "6"
        00032) + 2:0 ifne ->35
        00033) + 0:0 pushstring "6"
        00034) + 1:0 returnvalue
        00035) + 0:0 getlocal_1
        00036) + 1:0 pushstring "B"
        00037) + 2:0 ifne ->40
        00038) + 0:0 pushstring "7"
        00039) + 1:0 returnvalue
        00040) + 0:0 getlocal_1
        00041) + 1:0 pushstring "4"
        00042) + 2:0 ifne ->45
        00043) + 0:0 pushstring "8"
        00044) + 1:0 returnvalue
        00045) + 0:0 getlocal_1
        00046) + 1:0 pushstring "7"
        00047) + 2:0 ifne ->50
        00048) + 0:0 pushstring "9"
        00049) + 1:0 returnvalue
        00050) + 0:0 getlocal_1
        00051) + 1:0 pushstring "9"
        00052) + 2:0 ifne ->55
        00053) + 0:0 pushstring "A"
        00054) + 1:0 returnvalue
        00055) + 0:0 getlocal_1
        00056) + 1:0 pushstring "5"
        00057) + 2:0 ifne ->60
        00058) + 0:0 pushstring "B"
        00059) + 1:0 returnvalue
        00060) + 0:0 getlocal_1
        00061) + 1:0 pushstring "F"
        00062) + 2:0 ifne ->65
        00063) + 0:0 pushstring "C"
        00064) + 1:0 returnvalue
        00065) + 0:0 getlocal_1
        00066) + 1:0 pushstring "E"
        00067) + 2:0 ifne ->70
        00068) + 0:0 pushstring "D"
        00069) + 1:0 returnvalue
        00070) + 0:0 getlocal_1
        00071) + 1:0 pushstring "A"
        00072) + 2:0 ifne ->75
        00073) + 0:0 pushstring "E"
        00074) + 1:0 returnvalue
        00075) + 0:0 getlocal_1
        00076) + 1:0 pushstring "8"
        00077) + 2:0 ifne ->80
        00078) + 0:0 pushstring "F"
        00079) + 1:0 returnvalue
        00080) + 0:0 getlocal_1
        00081) + 1:0 returnvalue
    }
"""
Xxx = {
    "C" : "0",
    "3" : "1",
    "D" : "2",
    "0" : "3",
    "2" : "4",
    "1" : "5",
    "6" : "6",
    "B" : "7",
    "4" : "8",
    "7" : "9",
    "9" : "A",
    "5" : "B",
    "F" : "C",
    "E" : "D",
    "A" : "E",
    "8" : "F"
    }
def main():
    """TODO
    """
    with open( sys.argv[1], 'rb' ) as fh:
        c = fh.read()

    nc = map( lambda x: Xxx[x], c )

    with open( sys.argv[2], 'wb' ) as fh:
        for x in xrange( 0, len(nc), 2 ):
            fh.write( struct.pack('B', int(nc[x] + nc[x+1], 16)) )
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
