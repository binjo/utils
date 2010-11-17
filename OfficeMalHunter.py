#!/usr/bin/env python
# -*- coding: utf-8 -*-
# OfficeMalHunter.py
# Binjo @ 2009-06-01 16:35:41
# Reverse 4 phun...
#-------------------------------------------------------------------------------
import os, sys
from ctypes    import *
from pythoncom import *
from struct    import pack, unpack

k32  = windll.kernel32
libc = cdll.msvcrt
nt   = windll.ntdll

# RATING
# Malicious index rating:
#   Executables: 4
#   Code       : 3
#   STRINGS    : 2
#   OLE/NOPs   : 1
RATING_EXEC   = 4
RATING_CODE   = 3
RATING_STRS   = 2
RATING_OLENOP = 1

g_IndentNum   = 0
g_macro_flg   = 0
g_macro_dir   = ''
g_f_name      = ''
g_f_size      = 0
g_f_cnt       = None

g_power       = 0 # indicate the malicious power

A8            = c_byte * 8
g_aOfficeSig  = A8( 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 )

A6            = c_byte * 6
g_FldzSig     = A6( 0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4 )
g_CallPopSig1 = A6( 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58 )
g_CallPopSig2 = A6( 0xE8, 0x00, 0x00, 0x00, 0x00, 0x59 )
g_CallPopSig3 = A6( 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5A )
g_CallPopSig4 = A6( 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B )
g_CallPopSig5 = A6( 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E )
g_CallPopSig6 = A6( 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5F )
g_CallPopSig7 = A6( 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D )

A5            = c_byte * 5
g_FS30Sig1    = A5( 0x64, 0xA1, 0x30, 0x00, 0x00 ) # MOV EAX,DWORD PTR FS:[30]
g_FS30Sig2    = A5( 0x64, 0x8B, 0x1D, 0x30, 0x00 ) # MOV EBX,DWORD PTR FS:[30]
g_FS30Sig3    = A5( 0x64, 0x8B, 0x0D, 0x30, 0x00 ) # MOV ECX,DWORD PTR FS:[30]
g_FS30Sig4    = A5( 0x64, 0x8B, 0x15, 0x30, 0x00 ) # MOV EDX,DWORD PTR FS:[30]
g_FS30Sig5    = A5( 0x64, 0x8B, 0x35, 0x30, 0x00 ) # MOV ESI,DWORD PTR FS:[30]
g_FS30Sig6    = A5( 0x64, 0x8B, 0x3D, 0x30, 0x00 ) # MOV EDI,DWORD PTR FS:[30]

A3            = c_byte * 3
g_NopSig      = A3( 0x90, 0x90, 0x90 )

APIZ          = [
    'UrlDownloadToFile',
    'GetTempPath',
    'GetWindowsDirectory',
    'GetSystemDirectory',
    'WinExec',
    'IsBadReadPtr',
    'IsBadWritePtr',
    'CreateFile',
    'CloseHandle',
    'ReadFile',
    'WriteFile',
    'SetFilePointer',
    'VirtualAlloc',
    'GetProcAddr',
    'LoadLibrary']

def usage():
    """usage - show help here
    """
    h = k32.GetStdHandle( 0xFFFFFFF5 ) # STD_OUTPUT_HANDLE

    print "\nUsage:\n------\n",
    print "OfficeMalScanner <PPT, DOC or XLS file> <scan | info> <brute> <debug>\n",
    print "\nOptions:\n",
    print "  scan  - scan for several shellcode heuristics and encrypted PE-Files\n",
    print "  info  - dumps OLE structures, offsets+length and saves found VB-Macro code\n",
    print "\nSwitches: (only enabled if option \"scan\" was selected)",
    print "  brute - enables the \"brute force mode\" to find encrypted stuff\n",
    print "  debug - prints out disassembly resp hexoutput if a heuristic was found\n",
    print "\nExamples:\n",
    print "  OfficeMalScanner evil.ppt scan brute debug\n",
    print "  OfficeMalScanner evil.ppt scan\n",
    print "  OfficeMalScanner evil.ppt info\n",
    print "\nMalicious index rating:\n",
    print "  Executables: 4\n",
    print "  Code       : 3\n",
    print "  STRINGS    : 2\n",
    print "  OLE/NOPs   : 1\n",

    print "----------------------------------------------------------------------------\n",
    k32.SetConsoleTextAttribute( h, 0x14 ), #FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY ),
    print "    I strongly suggest you to scan malicious files in a safe environment\n",
    print " like VMWARE, as this tool is written in C and might have exploitable bugs!\n",
    k32.SetConsoleTextAttribute( h, 0x0F ), #FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY ),
    print "----------------------------------------------------------------------------\n",

    return -1

def save_decompressed_macro( name, buffer, idx ):
    """save decrompressed macro via RtlDecompressBuffer

    Arguments:
    - `name`:
    - `buffer`:
    - `idx`:
    """
    dec_data = create_string_buffer(0x800)
    final_size = c_ulong(0)

    nt.RtlDecompressBuffer(
        2,                        # COMPRESSION_FORMAT_LZNT1
        dec_data,                 # UncompressedBuffer
        0x800,                    # UncompressedBufferSize
        c_char_p(buffer[idx+1:]), # CompressedBuffer
        0xFFFFFF - idx,           # CompressedBufferSize
        byref(final_size)         # FinalUncompressedSize
        )

    try:
        if name == '': name = 'fvck'
        f = open( "%s\%s" % (g_macro_dir, name), 'wb' )
        f.write(dec_data.value)
    except Exception, e:
        print '[-] shit...%s' % e
    finally:
        f.close()

def dump_data( title, data, length ):
    """dump specific length of data

    Arguments:
    - `title`:
    - `data`:
    - `length`:
    """
    char_table = '................................ !\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`' \
        'abcdefghijklmnopqrstuvwxyz{|}~...............................................................................' \
        '..................................................'

    libc.printf( "\n[ %s - %u bytes ]\n", title, length )

    if len(data) < length: length = len(data)

    for i in xrange(1, length+1):
        libc.printf( "%02x ", unpack('B',data[i-1])[0] )
        if i % 8  == 0: libc.printf(" ")
        if i % 16 == 0:
            libc.printf("| ")
            j = i - 16
            while ( j < i ):
                libc.printf( "%s", char_table[unpack('B', data[j])[0]] )
                j += 1
            libc.printf("\n")

    if length % 16 != 0:
        m = 16 - length % 16
        n = 16 - length % 16
        while n:
            libc.printf( "   " )
            if n % 8 == 0 and m != 8:
                libc.printf(" ")
            n -= 1
        libc.printf(" | ")
        n = length - (16 - m)
        while n < length:
            libc.printf( "%s", char_table[unpack('B',data[n])[0]] )
            n += 1

    libc.printf("\n")
    print "--------------------------------------------------------------------------\n\n",

def print_stream_info( f, stg ):
    """print stream info

    Arguments:
    - `f`:
    - `stg`:
    """
    if stg is None:
        ost = StgOpenStorage( f, None, 0x10, None, 0 )
        print_stream_info( None, ost )
    else:
        estat = stg.EnumElements()

        if estat:
            s_info = estat.Next()
            while s_info != ():
                i = 0
                global g_IndentNum
                while i < g_IndentNum:
                    libc.printf(' ')
                    i += 1

                s_name = ''
                x_name = create_string_buffer(0x400)
                libc.wcstombs( x_name, c_wchar_p(s_info[0][0]), 0x400 )
                for c in x_name.value:
#                for c in s_info[0][0].encode( 'ascii', 'ignore' ):
                    if ord(c) > 122 or ord(c) <= 32: continue
                    s_name += c
                    libc.printf( c )

                if s_info[0][1] - 1 > 3:
                    print "   [TYPE: Unknown]\n",
                else:
                    # python don't support switch...
                    if s_info[0][1] == 1:
                        print "   [TYPE: Storage]\n",

                        x_stg = stg.OpenStorage( s_info[0][0], None, 0x10, None, 0 )
                        g_IndentNum += 1
                        print_stream_info( None, x_stg )
                        g_IndentNum -= 1

                    elif s_info[0][1] == 2:
                        print "   [TYPE: Stream",

                        macro  = 0
                        stream = stg.OpenStream( s_info[0][0], None, 0x10, 0 )
                        s_len  = s_info[0][2]
                        if s_len > 0x4000: s_len = 0x4000 # !!!!!!!!!!
                        data   = stream.Read( s_len )

                        if (unpack( 'B', data[0] )[0] != 1  or
                            unpack( 'B', data[1] )[0] != 22 or
                            unpack( 'B', data[2] )[0] != 1):
                            macro = 0
                        else:
                            for i in xrange(s_len - 3):
                                if (unpack( 'B', data[i] )[0] == 1 and
                                    unpack( 'B', data[i+1] )[0] and
                                    (unpack( 'B', data[i+2] )[0] & 0xF0 == 0xB0)):
                                    macro = 1
                                    global g_macro_flg
                                    g_macro_flg = 1
                                    break

                        if macro == 1:
                            global g_macro_dir
                            g_macro_dir = os.path.abspath( "%s\\%s-Macros" % (os.path.curdir, g_f_name) )
                            if not os.path.isdir( g_macro_dir ):
                                os.mkdir( g_macro_dir )
                            save_decompressed_macro( s_name, data, i )  # FIXME

                        for i in xrange( g_f_size ):
                            if ( libc.memcmp( c_char_p(g_f_cnt[i:]), c_char_p(data), 5) == 0 ):
                                print " - OFFSET: 0x%x - LEN: %lu]" % (i, s_len)
                                break

                    elif s_info[0][1] == 3:
                        print "   [TYPE: Lockbytes]\n",
                    elif s_info[0][1] == 4:
                        print "   [TYPE: Property]\n",

                s_info = estat.Next()

def print_opcodz( raw_data ):
    """print opcodz via Cadt.dll engine

    Arguments:
    - `raw_data`:
    """
    data = raw_data
    # cadt = cdll.LoadLibrary( 'Cadt.dll' )

    print ""

    # code = create_string_buffer(55)
    # asm  = create_string_buffer(44)
    # menm = create_string_buffer(1024)

    # for i in xrange(0x10):
    #     libc.memset( code, 0, 55 )
    #     libc.memset( asm,  0, 44 )
    #     c_len = windll.cadt.InstrDecode( c_char_p(data), code, 0 )
    #     windll.cadt.InstrDasm( code, asm, 0 )
    #     windll.cadt.MakeMnemonic( menm, asm, byref(c_int(1)) )
    #     data = data[c_len:]
    #     print "%s\n" % menm.value,

    from distorm import Decode, Decode32Bits

    l = Decode( 0x100, data, Decode32Bits )
    for i in l[:16]:
        print "%-20s %s" % (i[3], i[2])

def main():
    """TODO
    """
    mode_flg  = 0 # <scan | info> mode
    debug_flg = 0
    brute_flg = 0

    global g_power
    global g_f_cnt
    global g_f_size
    global g_f_name

    h = k32.GetStdHandle( 0xFFFFFFF5 )
    k32.SetConsoleTextAttribute( h, 0x03 ) # FOREGROUND_BLUE or FOREGROUND_GREEN

    # print title
    print "\n+------------------------------------------+\n",
    print "|           OfficeMalScanner v0.41         |\n",
    print "|  Frank Boldewin / www.reconstructer.org  |\n",
    print "+------------------------------------------+\n",

    k32.SetConsoleTextAttribute( h, 0x0F ) # FOREGROUND_BLUE or FOREGROUND_GREEN or FOREGROUND_RED or FOREGROUND_INTENSITY

    arg_len = len(sys.argv)
    if arg_len < 3 or arg_len > 5:
        usage()                                  # exit in usage...

    #
    # parse argvs
    #
    if sys.argv[2].upper() == "INFO":

        if arg_len != 3: usage()                 # exit in usage...
        print "\n[*] INFO mode selected\n",
        mode_flg = 1

    elif sys.argv[2].upper() == "SCAN":

        print "\n[*] SCAN mode selected\n",
        if arg_len > 3:
            i = 3
            while i < arg_len:
                if sys.argv[i].upper() == "DEBUG": debug_flg = 1
                if sys.argv[i].upper() == "BRUTE": brute_flg = 1
                i += 1
    else:
        usage()

    print "[*] Opening file %s\n" % sys.argv[1],
    try:
        f       = open( sys.argv[1], 'rb' )
        g_f_cnt = f.read()
        f.close()
    except:
        print "\nCannot open file %s\n" % sys.argv[1]
        exit(-2)

    g_f_size = len(g_f_cnt)

    print "[*] Filesize is %lu (0x%x) Bytes\n" % ( g_f_size, g_f_size ),

    # skip GetFileSize/CreateFileMappingA/MapViewOfFile, since it's PYTHON ;-p

    # if libc.memcmp( byref(g_aOfficeSig), g_f_cnt, 8 ) != 0:
    #     print "\nSorry, no PPT/DOC/XLS file!\n",
    #     print "If this is an Office 2007 file it can be extracted\n",
    #     print "with winzip and directly viewed with an XML-Editor!\n",
    #     exit(-6)
    # else:
    #     print "[*] Valid file format found.\n",

    if mode_flg == 1:
        """INFO"""
        g_f_name = os.path.basename(sys.argv[1])

        # python's print will append a space...
        libc.printf( "\n-----------------" )
        i = 0
        while i <= len(g_f_name) and i <= 62:
            libc.printf( "-" )
            i += 1
        libc.printf("\n")

        k32.SetConsoleTextAttribute( h, 0x03 ) # FOREGROUND_BLUE or FOREGROUND_GREEN
        print "[OLE Struct of: %s]\n" % g_f_name.upper(),
        k32.SetConsoleTextAttribute( h, 0x0F ) # FOREGROUND_BLUE or FOREGROUND_GREEN or FOREGROUND_RED or FOREGROUND_INTENSITY

        libc.printf( "-----------------" )
        i = 0
        while i <= len(g_f_name) and i <= 62:
            libc.printf( "-" )
            i += 1
        libc.printf("\n")

        print_stream_info( sys.argv[1], None )

        if g_macro_flg == 1:
            print "-----------------------------------------------------------------------------\n",
            k32.SetConsoleTextAttribute( h, 0x0E ) # FOREGROUND_GREEN or FOREGROUND_RED or FOREGROUND_INTENSITY
            print "                VB-MACRO CODE WAS FOUND INSIDE THIS FILE!\n",
            print "               The decompressed Macro code was stored here:\n\n------> %s\n" % os.path.abspath(g_macro_dir),
            k32.SetConsoleTextAttribute( h, 0x0F ) # FOREGROUND_BLUE or FOREGROUND_GREEN or FOREGROUND_RED or FOREGROUND_INTENSITY
            print "-----------------------------------------------------------------------------\n",
        else:
            print "-----------------------\n",
            print "No VB-Macro code found!\n",

    else:
        """SCAN"""
        print "[*] Scanning now...\n\n",

        for i in xrange(g_f_size):
            if ( libc.memcmp( byref(g_FS30Sig1), g_f_cnt[i:], 5 ) == 0 or
                 libc.memcmp( byref(g_FS30Sig2), g_f_cnt[i:], 5 ) == 0 or
                 libc.memcmp( byref(g_FS30Sig3), g_f_cnt[i:], 5 ) == 0 or
                 libc.memcmp( byref(g_FS30Sig4), g_f_cnt[i:], 5 ) == 0 or
                 libc.memcmp( byref(g_FS30Sig5), g_f_cnt[i:], 5 ) == 0 or
                 libc.memcmp( byref(g_FS30Sig6), g_f_cnt[i:], 5 ) == 0 ):
                print "FS:[30h] (Method 1) signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0x6A and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0x30 and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0x64 and
                 unpack( 'B', g_f_cnt[i+4] )[0] == 0x8B ):
                print "FS:[30] (Method 2) signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0x33 and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0xB3 and
                 unpack( 'B', g_f_cnt[i+4] )[0] == 0x64 and
                 unpack( 'B', g_f_cnt[i+5] )[0] == 0x8B ):
                print "FS:[30] (Method 3) signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0x74 and
                 unpack( 'B', g_f_cnt[i+2] )[0] == 0xC1 and
                 unpack( 'B', g_f_cnt[i+4] )[0] == 0x0D and
                 unpack( 'B', g_f_cnt[i+5] )[0] == 0x03 ):
                print "API-Hashing signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        i = 0
        while ( i < g_f_size ):
            if ( libc.memcmp( byref(g_NopSig), g_f_cnt[i:], 3 ) == 0 ):
                print "NOP slides signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                while unpack('B', g_f_cnt[i])[0] == 0x90: i += 1
                g_power += RATING_OLENOP
            i += 1

        for api in APIZ:
            for i in xrange(g_f_size):
                if libc.memcmp( c_char_p(api), g_f_cnt[i:], len(api) ) == 0:
                    print "API-Name %s string found at offset: 0x%x\n" % (api, i),
                    if debug_flg == 1: dump_data( "PE-File", g_f_cnt[i:], 0x100 )
                    g_power += RATING_STRS

        for i in xrange(8, g_f_size):
            if libc.memcmp( byref(g_aOfficeSig), g_f_cnt[i:], 8 ) == 0:
                print "Embedded OLE signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: dump_data( "PE-File", g_f_cnt[i:], 0x100 )
                g_power += RATING_OLENOP

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0x55 and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0x8B and
                 unpack( 'B', g_f_cnt[i+2] )[0] == 0xEC and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0x83 and
                 unpack( 'B', g_f_cnt[i+4] )[0] == 0xC4 ):
                print "Function prolog signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0x55 and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0x8B and
                 unpack( 'B', g_f_cnt[i+2] )[0] == 0xEC and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0x81 and
                 unpack( 'B', g_f_cnt[i+4] )[0] == 0xEC ):
                print "Function prolog signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0xFF and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0x75 and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0xFF and
                 unpack( 'B', g_f_cnt[i+4] )[0] == 0x55 ):
                print "PUSH DWORD[]/CALL[] signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0xAC and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0x34 and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0xAA ):
                print "LODSB/STOSB XOR decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0xAC and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0x04 and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0xAA ):
                print "LODSB/STOSB ADD decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0xAC and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0x2C and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0xAA ):
                print "LODSB/STOSB SUB decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0xAC and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0xD0 and
                 unpack( 'B', g_f_cnt[i+2] )[0] == 0xC0 and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0xAA ):
                print "LODSB/STOSB ROL decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0xAC and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0xD0 and
                 unpack( 'B', g_f_cnt[i+2] )[0] == 0xC8 and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0xAA ):
                print "LODSB/STOSB ROR decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0xAC and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0xC0 and
                 unpack( 'B', g_f_cnt[i+2] )[0] == 0xC0 and
                 unpack( 'B', g_f_cnt[i+4] )[0] == 0xAA ):
                print "LODSB/STOSB ROL decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0xAC and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0xC0 and
                 unpack( 'B', g_f_cnt[i+2] )[0] == 0xC8 and
                 unpack( 'B', g_f_cnt[i+4] )[0] == 0xAA ):
                print "LODSB/STOSB ROR decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0x66 and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0xAD and
                 unpack( 'B', g_f_cnt[i+2] )[0] == 0x66 and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0x35 and
                 unpack( 'B', g_f_cnt[i+6] )[0] == 0x66 and
                 unpack( 'B', g_f_cnt[i+7] )[0] == 0xAB ):
                print "LODSW/STOSW XOR decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0x66 and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0xAD and
                 unpack( 'B', g_f_cnt[i+2] )[0] == 0x66 and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0x05 and
                 unpack( 'B', g_f_cnt[i+6] )[0] == 0x66 and
                 unpack( 'B', g_f_cnt[i+7] )[0] == 0xAB ):
                print "LODSW/STOSW ADD decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0x66 and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0xAD and
                 unpack( 'B', g_f_cnt[i+2] )[0] == 0x66 and
                 unpack( 'B', g_f_cnt[i+3] )[0] == 0x2D and
                 unpack( 'B', g_f_cnt[i+6] )[0] == 0x66 and
                 unpack( 'B', g_f_cnt[i+7] )[0] == 0xAB ):
                print "LODSW/STOSW SUB decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0xAD and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0x35 and
                 unpack( 'B', g_f_cnt[i+6] )[0] == 0xAB ):
                print "LODSD/STOSD XOR decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0xAD and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0x05 and
                 unpack( 'B', g_f_cnt[i+6] )[0] == 0xAB ):
                print "LODSD/STOSD ADD decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i]   )[0] == 0xAD and
                 unpack( 'B', g_f_cnt[i+1] )[0] == 0x2D and
                 unpack( 'B', g_f_cnt[i+6] )[0] == 0xAB ):
                print "LODSD/STOSD SUB decryption signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if libc.memcmp( byref(g_FldzSig), g_f_cnt[i:], 6 ) == 0:
                print "FLDZ/FSTENV [esp-12] signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( libc.memcmp( byref(g_CallPopSig1), g_f_cnt[i:], 6 ) == 0 or
                 libc.memcmp( byref(g_CallPopSig2), g_f_cnt[i:], 6 ) == 0 or
                 libc.memcmp( byref(g_CallPopSig3), g_f_cnt[i:], 6 ) == 0 or
                 libc.memcmp( byref(g_CallPopSig4), g_f_cnt[i:], 6 ) == 0 or
                 libc.memcmp( byref(g_CallPopSig5), g_f_cnt[i:], 6 ) == 0 or
                 libc.memcmp( byref(g_CallPopSig6), g_f_cnt[i:], 6 ) == 0 or
                 libc.memcmp( byref(g_CallPopSig7), g_f_cnt[i:], 6 ) == 0 ):
                print "CALL next/POP signature found at offset: 0x%x\n" % i,
                if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i] )[0] == 0xEB and
                 unpack( 'B', g_f_cnt[i+unpack('B',g_f_cnt[i+1])[0]+2] )[0] == 0xE8 ):
                jmp_off  = i + unpack('B',g_f_cnt[i+1])[0] + 2
#                call_va  = unpack( '<L', g_f_cnt[jmp_off+1:jmp_off+5] )[0]  # python is much simple
                call_va  = unpack( 'B', g_f_cnt[jmp_off + 1] )[0]
                call_va += unpack( 'B', g_f_cnt[jmp_off + 2] )[0] << 8
                call_va += unpack( 'B', g_f_cnt[jmp_off + 3] )[0] << 16
                call_va += unpack( 'B', g_f_cnt[jmp_off + 4] )[0] << 24
                if ( jmp_off + call_va + 5 < g_f_size and
                     ( unpack( 'B', g_f_cnt[jmp_off+call_va+5] )[0] == 0x58 or
                       unpack( 'B', g_f_cnt[jmp_off+call_va+5] )[0] == 0x59 or
                       unpack( 'B', g_f_cnt[jmp_off+call_va+5] )[0] == 0x5A or
                       unpack( 'B', g_f_cnt[jmp_off+call_va+5] )[0] == 0x5B or
                       unpack( 'B', g_f_cnt[jmp_off+call_va+5] )[0] == 0x5E or
                       unpack( 'B', g_f_cnt[jmp_off+call_va+5] )[0] == 0x5F ) ):
                    print "JMP [0xEB]/CALL/POP signature found at offset: 0x%x\n" % i,
                    if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                    g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( unpack( 'B', g_f_cnt[i] )[0] == 0xE9 ):
#                jmp_off = unpack( '<L', g_f_cnt[i+1:i+5] )[0]
                jmp_off  = unpack( 'B', g_f_cnt[i + 1] )[0]
                jmp_off += unpack( 'B', g_f_cnt[i + 2] )[0] << 8
                jmp_off += unpack( 'B', g_f_cnt[i + 3] )[0] << 16
                jmp_off += unpack( 'B', g_f_cnt[i + 4] )[0] << 24

                if ( unpack( 'B', g_f_cnt[i+jmp_off+5] )[0] == 0xE8 ):
#                    call_va  = unpack( '<L', g_f_cnt[i+jmp_off+6:jmp_off+10] )[0]  # python is much simple
                    call_va  = unpack( 'B', g_f_cnt[i + jmp_off + 6] )[0]
                    call_va += unpack( 'B', g_f_cnt[i + jmp_off + 7] )[0] << 8
                    call_va += unpack( 'B', g_f_cnt[i + jmp_off + 8] )[0] << 16
                    call_va += unpack( 'B', g_f_cnt[i + jmp_off + 9] )[0] << 24
                    if not call_va:
                        if ( i + jmp_off + 10 < g_f_size and
                             ( unpack( 'B', g_f_cnt[i+jmp_off+10] )[0] == 0x58 or
                               unpack( 'B', g_f_cnt[i+jmp_off+10] )[0] == 0x59 or
                               unpack( 'B', g_f_cnt[i+jmp_off+10] )[0] == 0x5A or
                               unpack( 'B', g_f_cnt[i+jmp_off+10] )[0] == 0x5B or
                               unpack( 'B', g_f_cnt[i+jmp_off+10] )[0] == 0x5E or
                               unpack( 'B', g_f_cnt[i+jmp_off+10] )[0] == 0x5F ) ):
                            print "JMP [0xE9]/CALL/POP signature found at offset: 0x%x\n" % i,
                            if debug_flg == 1: print_opcodz( g_f_cnt[i:] )
                            g_power += RATING_CODE

        for i in xrange(g_f_size):
            if ( libc.memcmp( c_char_p("MZ"), g_f_cnt[i:], 2 ) == 0 ):
                pe_off  = unpack( 'B', g_f_cnt[i+0x3C] )[0]
                pe_off += unpack( 'B', g_f_cnt[i+0x3D] )[0] << 8
                pe_off += unpack( 'B', g_f_cnt[i+0x3E] )[0] << 16
                pe_off += unpack( 'B', g_f_cnt[i+0x3F] )[0] << 24
                if ( libc.memcmp( c_char_p("PE"), g_f_cnt[i+pe_off:], 2 ) == 0):
                    print "unencrypted MZ/PE signature found at offset: 0x%x\n" % i,
                    if debug_flg == 1: dump_data( "PE-File", g_f_cnt[i:], 0x100 )
                    g_power += RATING_EXEC

        if brute_flg == 1:
            print "\nBrute-forcing for encrypted PE- and embedded OLE-files now...\n",
            # TODO

        print "\n\nAnalysis finished!\n\n",

        if g_power:
            k32.SetConsoleTextAttribute( h, 0x0E ) # FOREGROUND_GREEN or FOREGROUND_RED or FOREGROUND_INTENSITY
            libc.printf( "---------------------------------------------" )
            i = 0
            while i < len(g_f_name):
                libc.printf("-")
                i += 1
            libc.printf( "\n%s seems to be malicious! Malicious Index = %02d\n", g_f_name, g_power )
            libc.printf( "---------------------------------------------" )
            i = 0
            while i < len(g_f_name):
                libc.printf("-")
                i += 1
            k32.SetConsoleTextAttribute( h, 0x0F ) # FOREGROUND_BLUE or FOREGROUND_GREEN or FOREGROUND_RED or FOREGROUND_INTENSITY
        else:
            k32.SetConsoleTextAttribute( h, 0x07 ) # FOREGROUND_BLUE or FOREGROUND_GREEN or FOREGROUND_RED
            print "---------------------------------------------------------------------\n",
            print "             No malicious traces found in this file!\n",
            print "Assure that this file is being scanned with the \"info\" parameter too.\n",
            print "---------------------------------------------------------------------\n",
            k32.SetConsoleTextAttribute( h, 0x0F ) # FOREGROUND_BLUE or FOREGROUND_GREEN or FOREGROUND_RED or FOREGROUND_INTENSITY

#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
