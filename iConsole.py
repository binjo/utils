# -*- coding : gb2312 -*-
# iConsole.py
# Binjo @ 2008-03-17 11:15:44
#-------------------------------------------------------------------------------
import os, sys
import subprocess
import md5
import vmrun
import pefile, peutils
import ctypes

TARGET   = ''
# default
VM_FILE  = r'D:\VMZ\XP_TRAIN\Windows XP Professional.vmx'
IC_HIEW  = r'D:\Tools\avtools\hiew7.2\hiew.exe'
SIG_FILE = r'D:\Tools\avtools\peid\userdb.txt'
# TODO
VM_ADMIN = 'administrator'
VM_PASS  = '12345'

def usage():
    print "iConsole> *USAGE* %s path\\to\\file" % os.path.basename( sys.argv[0] )
    exit

def error_act_handler( *para ):
    print "iConsole> Invalid CMD"

def set_vm( para ):
    '''
    set vm file path
    @para - foo.vmx's full path
    '''
    vm_file_path = para
    if os.path.isfile( vm_file_path ):
        global VM_FILE
        VM_FILE = vm_file_path
    else:
        print "iConsole> Invalid file path : %s" % vm_file_path

def start_vm( para ):
    '''
    start vm
    @para - foo.vmx's full path, if not specified use previous setted one
    '''
    vmx = VM_FILE
    if para != '':

        vm_file_path = para

        if not os.path.isfile( vm_file_path ):
            print "iConsole> Invalid file path : %s" % vm_file_path
            return

        vmx = vm_file_path

    assert vmx != ''

    vm = vmrun.Vmrun( vmx, VM_ADMIN, VM_PASS )
    vm.start()

def suspend_vm( para ):
    '''
    suspend vm
    @para - foo.vmx's full path, if not specified use previous setted one
    '''
    vmx = VM_FILE
    if para != '':

        vm_file_path = para

        if not os.path.isfile( vm_file_path ):
            print "iConsole> Invalid file path : %s" % vm_file_path
            return

        vmx = vm_file_path

    assert vmx != ''

    vm = vmrun.Vmrun( vmx, VM_ADMIN, VM_PASS )
    vm.suspend( 'hard' )

def stop_vm( para ):
    '''
    stop vm
    @para - foo.vmx's full path, if not specified use previous setted one
    '''
    vmx = VM_FILE
    if para != '':

        vm_file_path = para

        if not os.path.isfile( vm_file_path ):
            print "iConsole> Invalid file path : %s" % vm_file_path
            return

        vmx = vm_file_path

    assert vmx != ''

    vm = vmrun.Vmrun( vmx, VM_ADMIN, VM_PASS )
    vm.stop()

def take_snapshot( para ):
    pass

def copy_to_vm( para ):
    '''
    copy file to vm
    @para :
        if not specify para, means copy TARGET
        if only specify one parameter, means copy default
        if specify 2 parameters, means copy para1, and name it para2
    '''
    to_name = from_name = os.path.basename( TARGET )
    if para != '':
        names = para.split( " " )
        try:
            from_name = names[0]
            to_name   = names[1]
        except IndexError:
            from_name = os.path.basename( TARGET )
            to_name   = names[0]

    vm = vmrun.Vmrun( VM_FILE, VM_ADMIN, VM_PASS )
    vm.copyFileFromHostToGuest( from_name, "c:\\_virus\\%s" % to_name )

def get_from_vm( para ):
    '''
    get file from vm
    @para :
        if only specify parameter, means get default, dumped_.exe, and rename
        if specify 2 parameters, means get para1, and name it para2
    '''
    to_name = from_name = "dumped_.exe"
    cur_dir   = os.path.dirname( TARGET )
    if para != '':
        names = para.split( " " )
        try:
            from_name = names[0]
            to_name   = names[1]
        except IndexError:
            from_name = "dumped_.exe"
            to_name   = names[0]

    vm = vmrun.Vmrun( VM_FILE, VM_ADMIN, VM_PASS )
    vm.copyFileFromGuestToHost( "c:\\_virus\\%s" % from_name, "%s%s%s" % (cur_dir, os.path.sep, to_name) )

def start_ollydbg( para ):
    '''
    start ollydbg in the vm
    @para - file name to feed od
    '''
    file_name = "c:\\_virus\\%s" % os.path.basename( TARGET )
    if para != '':

        file_name = "c:\\_virus\\%s" % para

    vm = vmrun.Vmrun( VM_FILE, VM_ADMIN, VM_PASS )
    vm.runProgramInGuest( r'C:\\tools\\OllyICE\\OllyDBG.EXE', file_name )
#    vm.runProgramInGuest( r'C:\\tools\\odbg110\\OLLYDBG.EXE', file_name )

def revert_to_snap( para ):
    '''
    revert to snapshot
    @para - snapshot name
    '''
    if para == '':
        print "iConsole> specify snapshot name plz"
        return

    vm = vmrun.Vmrun( VM_FILE, VM_ADMIN, VM_PASS )
    vm.revertToSnapshot( para )

class win32_STARTUPINFO(ctypes.Structure):
    _fields_ = [
            ( 'cb',              ctypes.c_ulong  ),
            ( 'lpReserved',      ctypes.c_char_p ),
            ( 'lpDesktop',       ctypes.c_char_p ),
            ( 'lpTitle',         ctypes.c_char_p ),
            ( 'dwX',             ctypes.c_ulong  ),
            ( 'dwY',             ctypes.c_ulong  ),
            ( 'dwXSize',         ctypes.c_ulong  ),
            ( 'dwYSize',         ctypes.c_ulong  ),
            ( 'dwXCountChars',   ctypes.c_ulong  ),
            ( 'dwYCountChars',   ctypes.c_ulong  ),
            ( 'dwFillAttribute', ctypes.c_ulong  ),
            ( 'dwFlags',         ctypes.c_ulong  ),
            ( 'wShowWindow',     ctypes.c_ulong  ),
            ( 'cbReserved2',     ctypes.c_ulong  ),
            ( 'lpReserved2',     ctypes.c_ulong  ),
            ( 'hStdInput',       ctypes.c_void_p ),
            ( 'hStdOutput',      ctypes.c_void_p ),
            ( 'hStdError',       ctypes.c_void_p ),
            ]

class win32_PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
            ( 'hProcess',        ctypes.c_void_p ),
            ( 'hThread',         ctypes.c_void_p ),
            ( 'dwProcessId',     ctypes.c_ulong  ),
            ( 'dwThreadId',      ctypes.c_ulong  )
            ]

def exec_hiew( para ):
    '''
    execute hiew
    @para - file name
    '''
    file = TARGET

    if para != '':
        file = para

    if not os.path.isfile( file ):
        print "iConsole> *invalid* file"
        return

    startupInfo = win32_STARTUPINFO()
    processInfo = win32_PROCESS_INFORMATION()

    print "file = %s" % ctypes.c_char_p( file )
    ctypes.windll.kernel32.CreateProcessA( ctypes.c_char_p(IC_HIEW), file,#ctypes.c_char_p(file),
            None, None, False, 0x10, None, None, ctypes.pointer(startupInfo),ctypes.pointer(processInfo) )

def get_md5( para ):
    '''
    get file's md5 digest
    @para - file name
    '''
    file = TARGET

    if para != '':
        file = para

    if not os.path.isfile( file ):
        print "iConsole> *invalid* file"
        return

    fh = open( file, 'rb' )
    m  = md5.new()
    while 1:
        data = fh.read( 1024 )
        if not data:
            break
        m.update( data )

    print "iConsole> [MD5] %s : %s" % ( file, m.hexdigest() )
    fh.close()

def get_packer_info( para ):
    '''
    get information about packer
    @para - file name
    '''
    file = TARGET

    if para != '':
        file = para

    if not os.path.isfile( file ):
        print "iConsole> *invalid* file"
        return

    pe     = pefile.PE( file )
    sig    = peutils.SignatureDatabase( SIG_FILE )
    packer = sig.match( pe )
    print "iConsole> %s" % packer

ACTIONS = {
        "set_vm"        :   set_vm,
        "start"         :   start_vm,
        "suspend"       :   suspend_vm,
        "stop"          :   stop_vm,
        "snap"          :   take_snapshot,
        "revert"        :   revert_to_snap,
        "cp"            :   copy_to_vm,
        "get"           :   get_from_vm,
        "od"            :   start_ollydbg,
        "hiew"          :   exec_hiew,
        "md5"           :   get_md5,
        "pk"            :   get_packer_info
        }

def iDispatcher( cmd ):

    cmd = cmd.strip( ' ' )

    # FIXME
    try:
        if cmd.index( ',' ):
            cmd_list = cmd.split( ',' )
            for kmd in cmd_list:
                iDispatcher( kmd )
        return
    except:
        pass

    cmds = cmd.split( " ", 1 )
    act = cmds[0]
    try:
        params = cmds[1]
    except IndexError:
        params = ''

    if act != '':
        ACTIONS.get( act, error_act_handler )( params )

def main():
    """
    TODO
    """

    TITLE = '          .__ _________                                 .__            \n' \
            '          |__|\_   ___ \   ____    ____    ______ ____  |  |    ____   \n' \
            '          |  |/    \  \/  /  _ \  /    \  /  ___//  _ \ |  |  _/ __ \  \n' \
            '          |  |\     \____(  <_> )|   |  \ \___ \(  <_> )|  |__\  ___/  \n' \
            '          |__| \______  / \____/ |___|  //____  >\____/ |____/ \___  > \n' \
            '                      \/              \/      \/                   \/  \n'

    print TITLE

    try:
        global TARGET
        TARGET = sys.argv[1]
        if not os.path.isfile( TARGET ):
            print "iConsole> %s is *NOT* a valid file" % TARGET
            return
    except IndexError:
        usage()

    cmd = raw_input( "iConsole> " )
    while cmd.lower() != 'q':
        iDispatcher( cmd )
        cmd = raw_input( "iConsole> " )

#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
