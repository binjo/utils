#!/usr/bin/env python
# -*- coding : utf-8 -*-

"""
iConsole.py


"""
__author__  = 'Binjo'
__version__ = '0.2'
__date__    = '2008-03-17 11:15:44'

import os, sys
import subprocess
import md5
import pefile, peutils
import ctypes
import pprint as pp
from vmrun import Vmrun
from cmd   import *

TARGET   = ''
# default
VM_FILE  = r'D:\VMZ\XP_TRAIN\Windows XP Professional.vmx'
IC_HIEW  = r'D:\Tools\avtools\hiew7.2\hiew.exe'
SIG_FILE = r'D:\Tools\avtools\peid\userdb.txt'
# TODO
VM_ADMIN = 'administrator'
VM_PASS  = '12345'

class BaseUI(Cmd):
    """The base User Interface Object.
    """
    path = []
    name = ""

    def __init__(self):
        """
        """
        Cmd.__init__(self)

    def make_prompt(self, name=""):
        test_str = self.get_prompt()
        if test_str.endswith(name):
            test_str += "> "
            return(test_str)
        #the above is a little hack to test if the path
        #is already set for us, incase this object instance
        #is actually getting reused under the hood.
        self.path.append(name)
        tmp_name = ""
        tmp_name = self.get_prompt()
        tmp_name += "> "
        return(tmp_name)

    def get_prompt(self):
        tmp_name = ""
        for x in self.path: #iterate through object heirarchy
            tmp_name += (x)
        return tmp_name

    def do_help(self, args):
        """

        Arguments:
        - `self`:
        - `args`:
        """
        Cmd.do_help(self, args)

    def do_hist(self, args):
        """Display command history.

        Arguments:
        - `self`:
        - `args`:
        """
        pp.pprint(self._hist)

    def emptyline(self):
        """pass

        Arguments:
        - `self`:
        """
        pass

    def preloop(self):
        """

        Arguments:
        - `self`:
        """
        Cmd.preloop(self)
        self._hist = []

    def postloop(self):
        """bye

        Arguments:
        - `self`:
        """
        Cmd.postloop(self)
        print "\nExiting..."

    def precmd(self, line):
        """save line as history.

        Arguments:
        - `self`:
        - `line`:
        """
        self._hist += [line.strip()]
        return line

    def postcmd(self, stop, line):
        """

        Arguments:
        - `self`:
        - `stop`:
        - `line`:
        """
        return stop

    def default(self, line):
        """unrecognized cmd.

        Arguments:
        - `self`:
        - `line`:
        """
        print "\nBad command : %s" % line

    def do_exit(self, args):
        """Exit

        Arguments:
        - `self`:
        - `args`:
        """
        return -1

    do_q = do_EOF = do_exit

    def checkargs(self, args, num_args=None):
        """
        A utility function to split up the args.
        Also check check the number of args against
        a number of arguments
        """
        splitted_args = args[0].split(' ')
        if splitted_args.__contains__(''):
            splitted_args.remove('')
        if num_args == None:
            return splitted_args
        if (len(splitted_args) < num_args):
            print "Incorrect number of arguments."
            return
        else:
            return splitted_args

class MasterUI(BaseUI):
    """
    """
    vm_file  = ""
    vm_admin = "administrator"
    vm_pass  = "12345"

    def __init__(self, prompt, intro):
        """

        Arguments:
        - `prompt`:
        - `intro`:
        """
        BaseUI.__init__(self)
        self.prompt       = self.make_prompt(prompt)
        self.intro        = intro
        self.doc_header   = "...oooOOO iConsole Command OOOooo..." \
            "\n (for help, type: help <command>)"
        self.undoc_header = ""
        self.misc_header  = ""
        self.ruler        = " "

        if ( os.path.isfile( self.vm_file ) and
             self.vm_admin != "" and
             self.vm_pass  != "" ):
            self.vmrun    = Vmrun( self.vm_file, self.vm_admin, self.vm_pass )

    def do_vmset(self, *args):
        """
        Set vm file path

        Usage:
            vmset c:/path/to/vm.vmx
        """
        # FIXME can't parse option when path has space
        # args = self.checkargs(args, 1)

        if args == None: return

        vmx = args[0]
        if os.path.isfile( vmx ):
            self.vm_file = vmx

    def do_vmstart(self, *args):
        """
        Start vm

        Usage:
            vmstart [c:/path/to/vm.vmx]
        """
        # FIXME can't parse option when path has space
        # args = self.checkargs(args)
        if len(args) == 1 and os.path.isfile( args[0] ):
            self.vm_file = args[0]
            self.vmrun = Vmrun( self.vm_file, self.vm_admin, self.vm_pass )

        self.vmrun.start()

    def do_vmsuspend(self, *args):
        """
        Suspend vm

        Usage:
            vmsuspend [c:/path/to/vm.vmx]
        """
        if len(args) == 1 and os.path.isfile( args[0] ):
            self.vm_file = args[0]
            self.vmrun = Vmrun( self.vm_file, self.vm_admin, self.vm_pass )

        self.vmrun.suspend( "hard" )

    def do_vmstop(self, *args):
        """
        Suspend vm

        Usage:
            vmstop [c:/path/to/vm.vmx]
        """
        if len(args) == 1 and os.path.isfile( args[0] ):
            self.vm_file = args[0]
            self.vmrun = Vmrun( self.vm_file, self.vm_admin, self.vm_pass )

        self.vmrun.stop()

    def do_vmsnapshot(self, *args):
        """
        Take snapshot

        Usage:
            vmsnapshot ....
        """
        # TODO
        pass

    def do_vmcopy(self, *args):
        """
        Copy file to vm

        Usage:
            vmcopy from to
        """
        args = self.checkargs(args, 2)

        if args == None: return

        if self.vmrun is not None:
            # TODO change path
            self.vmrun.copyFileFromHostToGuest( args[0], "c:\\_virus\\%s" % args[1] )

    def do_vmget(sef, *args):
        """
        Get file from vm

        Usage:
            vmget file_of_vm as_file_host
        """
        args = self.checkargs(args, 2)

        if args == None: return

        if self.vmrun is not None:
            self.vmrun.copyFileFromHostToGuest( "c:\\_virus\\%s" % args[0],
                                                args[1] )

    def do_vmrevert(self, *args):
        """
        Rever to snapshot

        Usage:
            vmrevert snapshot_name
        """
        args = self.checkargs(args, 1)

        if args == None: return

        if self.vmrun is not None:
            self.vmrun.revertToSnapshot( args[0] )

    def do_vmod(self, *args):
        """
        Start ollydbg in the vm, for now file must stay in folder of "c:\_virus"...

        Usage:
            vmod file
        """
        args = self.checkargs(args, 1)

        if args == None: return

        # TODO hardcoded path
        fn = "c:\\_virus\\%s" % args[0]

        if self.vmrun is not None:
            self.vmrun.runProgramInGuest( r'C:\\tools\\OllyICE\\OllyDBG.EXE', fn )

    def do_md5(self, *args):
        """
        Get file's md5 digest

        Usage:
            md5 file
        """
        args = self.checkargs(args, 1)

        if args == None: return

        if not os.path.isfile(args[0]):
            print "*invalid* file : %s" % args[0]
            return

        fh = open( args[0], "rb" )
        m  = md5.new()
        while True:
            data = fh.read(1024)
            if not data: break
            m.update(data)

        print "[MD5] %s : %s" % (args[0], m.hexdigest())
        fh.close()

    def do_pkinfo(self, *args):
        """
        Get pe's packer info

        Usage:
            pkinfo file
        """
        args = self.checkargs(args, 1)

        if args == None: return

        fn = args[0]
        if not os.path.isfile(fn):
            print "*invalid* file : %s" % fn
            return

        pe  = pefile.PE(fn)
        sig = peutils.SignatureDatabase( SIG_FILE )
        pk  = sig.match(pe)
        print "[pkinfo] %s : %s" % (fn, pk)

#-------------------------------------------------------------------------------
if __name__ == '__main__':
    welcome = """

                    ...oooOOO Welcome to OOOooo...

          .__ _________                                 .__
          |__|\_   ___ \   ____    ____    ______ ____  |  |    ____
          |  |/    \  \/  /  _ \  /    \  /  ___//  _ \ |  |  _/ __ \
          |  |\     \____(  <_> )|   |  \ \___ \(  <_> )|  |__\  ___/
          |__| \______  / \____/ |___|  //____  >\____/ |____/ \___  >
                      \/              \/      \/                   \/

                    ...oooOOOOOOOOOOOOOOOOOOooo...
"""
    MasterUI( "iConsole", welcome ).cmdloop()
#-------------------------------------------------------------------------------
# EOF
