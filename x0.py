#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
x0.py

md5: c31341df029e6dc2804ba2f97db7baf7

seg000:00000192 C7 85 04 06 00 00 00 04+                mov     dword ptr [ebp+604h], 400h
seg000:0000019C
seg000:0000019C                         loc_19C:                                ; CODE XREF: seg000:00000216
seg000:0000019C 6A 00                                   push    0
seg000:0000019E 8D 85 00 07 00 00                       lea     eax, [ebp+700h]
seg000:000001A4 50                                      push    eax
seg000:000001A5 68 00 04 00 00                          push    400h
seg000:000001AA 8D 85 00 02 00 00                       lea     eax, [ebp+200h]
seg000:000001B0 50                                      push    eax
seg000:000001B1 8B 77 34                                mov     esi, [edi+34h]
seg000:000001B4 56                                      push    esi
seg000:000001B5 FF 57 F4                                call    dword ptr [edi-0Ch]
seg000:000001B8 8B C3                                   mov     eax, ebx
seg000:000001BA 2D 00 04 00 00                          sub     eax, 400h
seg000:000001BF 83 F8 00                                cmp     eax, 0
seg000:000001C2 7F 06                                   jg      short loc_1CA
seg000:000001C4 89 9D 04 06 00 00                       mov     [ebp+604h], ebx
seg000:000001CA
seg000:000001CA                         loc_1CA:                                ; CODE XREF: seg000:000001C2
seg000:000001CA 33 C9                                   xor     ecx, ecx
seg000:000001CC
seg000:000001CC                         loc_1CC:                                ; CODE XREF: seg000:000001EC
seg000:000001CC 8D B4 0D 00 02 00 00                    lea     esi, [ebp+ecx+200h]
seg000:000001D3 AC                                      lodsb
seg000:000001D4 32 C1                                   xor     al, cl          ; 0xff & i % 0x400
seg000:000001D6 C0 C8 03                                ror     al, 3           ; y >> 3 ^ 0xff & y << 5
seg000:000001D9 87 FA                                   xchg    edi, edx
seg000:000001DB 8D BC 0D 00 02 00 00                    lea     edi, [ebp+ecx+200h]
seg000:000001E2 AA                                      stosb
seg000:000001E3 87 FA                                   xchg    edi, edx
seg000:000001E5 41                                      inc     ecx
seg000:000001E6 3B 8D 04 06 00 00                       cmp     ecx, [ebp+604h]
seg000:000001EC 75 DE                                   jnz     short loc_1CC
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2010-12-22 15:16:39'

import os, sys
import struct as s

def main():
    """TODO
    """
    c = open( sys.argv[1], "rb" ).read()

    f = open( sys.argv[2], "wb" )

    i = 0
    for x in c[int(sys.argv[3], 16):]:
        y, i = s.unpack("B", x)[0] ^ (0xff&i%0x400), i + 1
        f.write( s.pack("B", y>>3^0xff&y<<5) )
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
