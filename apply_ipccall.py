#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
apply_ipccall.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2013-03-18 22:30:00'

import os, sys, re
import idc, idautils

def register_structs():
    """register
    """
    fpth = os.path.join( os.path.dirname( __file__ ), 'mysandbox.h' )
    defs = open( fpth, 'rb').read()

    for struct in re.finditer( "(?P<def>^\w+\s+(?P<name>_\S+)\r?\n{[^}]+?};)", defs, re.M ):

        fed = struct.group('def')
        nme = struct.group('name')

        rc = SetLocalType( -1, fed, 0 )
        if rc == 0:
            print '[-] failed to set definition of [%s]' % nme
            continue            # FIXME return?

        print '> importing type of %s' % nme
        rc = Til2Idb( -1, nme )
        if rc == BADNODE:
            print '[-] failed...'
            continue            # FIXME return?

    print '[+] register structs done...'

def resolve_AddCrossCall():
    """
    """
    # searching HandlerInternetConnectA's param type info
    ea = FindBinary( MinEA(), SEARCH_DOWN, '04 00 00 00 07 00 00 00 02 00 00 00 07 00 00 00 07 00 00 00 02 00 00 00 02 00 00 00 02 00 00 00' )

    if BADADDR == ea:
        print '[-] failed to find binary pattern of HandlerInternetConnectA param type info'
        return BADADDR

    push_ea = DfirstB( ea-4 )
    call_ea = NextHead( NextHead(push_ea) )

    ae = GetOperandValue( call_ea, 0 )

    print '[+] find AddCrossCall @', hex(ae)
    MakeName( ae, 'AddCrossCall' )

    return ae

def resolve_InterceptXxx():
    """
    """
    # searching InterceptXxx call sequence
    ea = FindBinary( MinEA(), SEARCH_DOWN, '6A ?? 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8' )

    if BADADDR == ea:
        print '[-] failed to find binary pattern of InterceptXxx call sequence'
        return BADADDR

    call_ea = NextHead( NextHead( NextHead( NextHead( NextHead(ea) ) ) ) )

    ae = GetOperandValue( call_ea, 0 )

    print '[+] find InterceptXxx @', hex(ae)
    MakeName( ae, 'InterceptXxx' )

    return ae

def resolve_GetGlobalIPCMemory():
    """resolve GetGlobalIPCMemory ea
    """
    ea = FindBinary( MinEA(), SEARCH_DOWN, 'E8 ?? ?? ?? ?? 84 C0 75 03 33 C0 C3' )

    if BADADDR == ea:
        print '[-] failed to find binary of GetGlobalIPCMemory'
        return

    print '[+] GetGlobalIPCMemory @', hex(ea)
    MakeName( ea, 'GetGlobalIPCMemory' )

def resolve_Docall():
    """resolve Docall ea
    """
    ea = FindBinary( MinEA(), SEARCH_DOWN, '68 E8 03 00 00 ?? ?? 89 ?? 10' )
    if BADADDR == ea:
        print '[-] failded to find binary of Docall pattern1'
        return

    ae = FindBinary( ea, SEARCH_UP, '55 8B EC' )
    if BADADDR == ae:
        print '[-] failded to find binary of Docall pattern2'
        return

    print '[+] SharedMemIPCClient::DoCall @', hex(ae)
    MakeName( ae, 'SharedMemIPCClient::DoCall' )

def resolve_GetBuffer():
    """resolve GetBuffer ea
    """
    ea = FindBinary( MinEA(), SEARCH_DOWN, '55 8B EC 51 56 8D 45 FF 50 8B F1' )

    if BADADDR == ea:
        print '[-] failed to find binary of GetBuffer'
        return

    print '[+] SharedMemIPCClient::GetBuffer @', hex(ea)
    MakeName( ea, 'SharedMemIPCClient::GetBuffer' )

def resolve_FreeBuffer():
    """resolve FreeBuffer ea
    """
    ea = FindBinary( MinEA(), SEARCH_DOWN, '2B 41 04 8B 09 C1 E8 11 8D 04 80 6A 01 8D 54 81 0C' )
    if BADADDR == ea:
        ea = FindBinary( MinEA(), SEARCH_DOWN, 'E8 ?? ?? ?? ?? 8B 0E 83 C1 08 8D 14 80 6A 01 8D 8D 44 91 04 50 FF' )
        if BADADDR == ea:
            print '[-] failded to find binary of FreeBuffer pattern1'
            return

    ae = FindBinary( ea, SEARCH_UP, '55 8B EC' )
    if BADADDR == ae:
        print '[-] failded to find binary of Docall pattern2'
        return

    print '[+] SharedMemIPCClient::FreeBuffer @', hex(ae)
    MakeName( ae, 'SharedMemIPCClient::FreeBuffer' )

def resolve_SharedMemIPCClient():
    """resolve SharedMemIPCClient ea
    """
    # ea = FindBinary( MinEA(), SEARCH_DOWN, '55 8B EC 51 8B C1 8B 4D 08 89 08 8B 51 08 03 D1 C7 45 FC 00 00 00 00 89 50 04 8B E5 5D C2 04 00' )
    ea = FindBinary( MinEA(), SEARCH_DOWN, 'C1 8B 4D 08 89 08 8B 51 08 03 D1 C7 45 FC 00 00 00 00 89 50 04 8B E5 5D C2 04 00' )
    if BADADDR == ea:
        ea = FindBinary( MinEA(), SEARCH_DOWN, '89 ?? 8B ?? 08 03' )
        if BADADDR == ea:
            print '[-] failded to find binary of SharedMemIPCClient pattern1'
            return

    ae = FindBinary( ea, SEARCH_UP, '55 8B EC' )
    if BADADDR == ae:
        print '[-] failded to find binary of SharedMemIPCClient pattern2'
        return

    print '[+] SharedMemIPCClient::SharedMemIPCClient @', hex(ae)
    MakeName( ae, 'SharedMemIPCClient::SharedMemIPCClient' )

def backward_push_offset(ea, num):
    """search push operand backward, for specified total num
    """
    pushee = []

    while True:

        if len(pushee) == num:
            break

        mnem = GetMnem(ea)
        if mnem == 'push':
            pushee.append( GetOperandValue(ea, 0) )

        if not isCode(GetFlags(ea)):
            break

        ea = PrevHead(ea)

    return pushee

def apply_ipccall(ea):
    """apply _IPCCall struct
    """
    prev_name = Name(ea)
    tag_id = Dword(ea)
    print 'tag id = %04X' % tag_id

    if ( prev_name.find('unk_') == 0
         or prev_name.find('stru_') == 0 ):

        # apply _IPCCall struct
        MakeStruct( ea, '_IPCCall' )

        # rename struct
        cur_name = 'ipc_%04x_tag' % tag_id
        print '%s -> %s' % (prev_name, cur_name)
        MakeName( ea, cur_name )

    # rename callback
    callback = Dword(ea+0x38)
    cbname = Name(callback)

    if cbname.find('sub_') == 0:
        cbnew = 'HandlerCallback%04X' % tag_id
        print 'callback, %s -> %s' % (cbname, cbnew)
        MakeName( callback, cbnew )

    print '-------[%s]-------' % Name( callback )

    # set function comment with tag id
    SetFunctionCmt( callback, Name(ea), 1 )

    calls = collect_calls( callback )
    print 'total calls = %d' % len(calls)
    for ea, func, name in calls:
        print hex(ea), hex(func), name

def collect_calls(ea):
    """collect calls within function
    """
    calls = []
    for iea in FuncItems(ea):
        mnem = GetMnem(iea)
        otyp = GetOpType(iea, 0)
        if mnem == 'call' and (o_mem == otyp or o_far == otyp or o_near == otyp):
            func_ea = GetOperandValue(iea, 0)
            calls.append( (iea, func_ea, GetDisasm(iea).lstrip('call ') ) )

    return calls

def infer_tag(ea):
    """try to collect all push within sub
    """
    pushee = []
    ea_end = FindFuncEnd(ea)
    while ea < ea_end:          # FIXME possilbe tail trunk?
        mnem = GetMnem(ea)
        if mnem == 'push' and GetOpType(ea, 0) == o_imm:
            oprnd = GetOperandValue(ea, 0)
            if oprnd >=0 and oprnd < 0x105:
                pushee.append( (ea, oprnd) )
        ea = NextHead(ea)       # NextNotTail

    return pushee

def resolve_pfns():
    """try to resolve pfn names
    """
    print '> rolling pfns...'
    ctn = 0
    for xref in XrefsTo(0x402C50): # get_proc_address
        next_ea = NextHead( xref.frm )
        if GetMnem(next_ea) == 'mov' and GetOpnd(next_ea, 1) == 'eax':
            pfn_ea = GetOperandValue( next_ea, 0 )
            apiname_ea = backward_push_offset(xref.frm, 1)[0]
            apiname = GetString( apiname_ea )
            MakeName( pfn_ea, 'pfn' + apiname )
            print hex(ctn), hex(pfn_ea), apiname
            ctn += 1

def main():
    """TODO
    """
    register_structs()

    print '> resolving ipc key funcs...'
    resolve_GetGlobalIPCMemory()
    resolve_Docall()
    resolve_GetBuffer()
    resolve_FreeBuffer()
    resolve_SharedMemIPCClient()

    # IPCCall
    print '> rolling ipccall...'
    add_ipc_call = resolve_AddCrossCall()
    if BADADDR != add_ipc_call:

        cnt = 0
        for xref in XrefsTo( add_ipc_call ):
            pushee = backward_push_offset( xref.frm, 1 )
            print '[%08x] apply _IPCCall @ 0x%08x' % (cnt, pushee[0])
            apply_ipccall( pushee[0] )
            cnt += 1

    # intercepted
    print '> rolling intercepted...'
    intercept_xxx = resolve_InterceptXxx()
    if BADADDR != intercept_xxx:
        cnt = 0
        for xref in XrefsTo( intercept_xxx ):
            pushee = backward_push_offset( xref.frm, 5 )
            dll = GetString( pushee[0], strtype=ASCSTR_UNICODE )
            if not dll:
                dll = 'FIXME.xxx'   # awkward fix
            api = GetString( pushee[1] )
            intercept_func_name = 'Intercepted_%s_%s' % (dll.split('.')[0], api)
            print '[%08x] 0x%08x, interception type = 0x%08x, unknown var = 0x%08x, %s' % \
                (cnt, xref.frm, pushee[2], pushee[4], intercept_func_name )
            MakeName( pushee[3], intercept_func_name )
            possible_tags = infer_tag( pushee[3] )
            if len(possible_tags) != 0:
                print '>infer possible tag...'
                for et in possible_tags:
                    print hex(et[0]), hex(et[1])
            cnt += 1
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
