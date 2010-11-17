#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__      = "Binjo"
__version__     = "0.3"
__date__        = "2008-03-17 11:15:44"
__description__ = """
iConsole.py

console rulz...
"""

import os, sys
import subprocess
import hashlib
import pefile, peutils
import ctypes
import pprint as pp
import optparse
from vmrun        import Vmrun
from cmd          import *
from ConfigParser import *

def string2args(arg):
    """convert string `arg' to a list of argument.

    Arguments:
    - `arg`:
    """
    argv = []
    quotation_mark = False

    for x in arg.split(" "):

        if x == "": continue

        if (not quotation_mark and ( x.startswith("\"") or x.startswith("'") )):
            quotation_mark = True
            x = x[1:]
            argv.append(x)

        elif (quotation_mark and ( x.endswith("\"") or x.endswith("'") )):
            quotation_mark = False
            x = x[:-1]
            argv[-1] += " %s" % x

        elif quotation_mark:
            argv[-1] += " %s" % x

        else:
            argv.append(x)

    return argv

class VmxUI(Cmd):
    """The base User Interface Object.
    """
    path      = []
    name      = ""

    vmx       = None
    vmx_admin = None
    vmx_pass  = None
    cwd_guest = None

    cwd_host  = None

    def __init__(self, config='.config'):
        """
        """
        Cmd.__init__(self)
        if os.path.exists(config):
            self.cfg = RawConfigParser()
            self.cfg.read(config)

        try:
            self.cwd_host = self.cfg.get( "host", "cwd" )
        except:
            self.cwd_host = os.getcwd()

    def init_vmx(self, section):
        """initialize vmx releated settings via specified section of config

        Arguments:
        - `self`:
        - `section`:
        """
        try:
            self.section   = section
            self.vmx       = self.cfg.get( section, "vmx" )
            self.vmx_admin = self.cfg.get( section, "admin" )
            self.vmx_pass  = self.cfg.get( section, "pass" )
            self.cwd_guest = self.cfg.get( section, "cwd" )
        except Exception, e:
            print "[-] error init_vmx: %s" % str(e)

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

    def do_set(self, args):
        """set configs

        Arguments:
        - `self`:
        - `args`:
        """
        argv = self.checkargs(args)
        if len(argv) == 0:
            for sec in self.cfg.sections():
                print "[%s]" % sec
            print "for more information, please type 'show'"
        elif len(argv) == 3:
            self.cfg.set( argv[0], argv[1], argv[2] )
        else:
            print "[-] invalid args"

    def do_show(self, args):
        """show specifical settings

        Arguments:
        - `self`:
        - `args`:
        """
        argv = self.checkargs(args, 1)
        if argv is not None:
            try:
                sec = argv[0]
                print "[%s]" % sec
                for n, v in self.cfg.items(sec):
                    print "%s => %s" % (n, v)
            except NoSectionError, e:
                print "[-] error : %s" % str(e)

    def do_use(self, args):
        """use specified vmx file

        Arguments:
        - `self`:
        - `args`:
        """
        argv = self.checkargs(args, 1)
        if argv is not None:
            if self.cfg.has_section( "vmx-%s" % argv[0] ):
                self.init_vmx( "vmx-%s" % argv[0] )
            else:
                print "[-] error : %s vmx settings *NOT* exists"

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

    def do_pwd(self, args):
        """Display current directory of Guest.
        """
        if self.cwd_guest is not None:
            print self.cwd_guest
        else:
            print "type 'use' first..."

    def do_lpwd(self, args):
        """Display current display of Host.
        """
        print self.cwd_host

    def do_cd(self, args):
        """cd in guest

        Arguments:
        - `self`:
        - `args`:
        """
        argv = self.checkargs(args, 1)
        if argv is not None:
            if self.cwd_guest is not None:
                self.cwd_guest = argv[0]
            else:
                print "type 'use' first..."

    def do_lcd(self, args):
        """cd in host

        Arguments:
        - `self`:
        - `args`:
        """
        os.chdir(args)
        self.cwd_host = os.getcwd()

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
        argv = string2args(args)
        if num_args == None:
            return argv
        if (len(argv) < num_args):
            print "Incorrect number of arguments."
            return
        else:
            return argv

class ConsoleUI(VmxUI):
    """
    """
    vmrun = None

    def __init__(self, prompt, intro, config='.config', debug=False):
        """

        Arguments:
        - `prompt`:
        - `intro`:
        """
        VmxUI.__init__(self, config)
        self.prompt       = self.make_prompt(prompt)
        self.intro        = intro
        self.doc_header   = "...oooOOO iConsole Command OOOooo..." \
            "\n (for help, type: help <command>)"
        self.undoc_header = ""
        self.misc_header  = ""
        self.ruler        = " "
        self.debug        = debug

    # FIXME awkward assert...
    def assert_vmrun(self):
        """Assert vmrun is properly initialized.

        Arguments:
        - `self`:
        """
        if self.vmrun is None:
            print "type 'use' first..."
            return 0
        else:
            return 1

    def do_use(self, args):
        """use specified vmx file, and initialize vmrun.

        Usage:
            use vmx-name
        """
        VmxUI.do_use(self, args)
        if ( self.vmx is not None and
             self.vmx_admin is not None and
             self.vmx_pass is not None ):
            self.vmrun = Vmrun( self.vmx, self.vmx_admin, self.vmx_pass, debug=self.debug )

    def do_vmstart(self, args):
        """
        Start vm

        Usage:
            vmstart
        """
        return self.assert_vmrun() and "".join( self.vmrun.start() )

    do_start = do_vmstart

    def do_vmsuspend(self, args):
        """
        Suspend vm

        Usage:
            vmsuspend
        """
        return self.assert_vmrun() and "".join( self.vmrun.suspend( "hard" ) )

    do_suspend = do_vmsuspend

    def do_vmstop(self, args):
        """
        Suspend vm

        Usage:
            vmstop
        """
        return self.assert_vmrun() and "".join( self.vmrun.stop() )

    do_stop = do_vmstop

    def do_vmcopy(self, args):
        """
        Copy file to vm

        Usage:
            vmcopy from to
        """
        argv = self.checkargs(args, 2)

        if argv == None: return

        # TODO change path
        return self.assert_vmrun() and \
            "".join( self.vmrun.copyFileFromHostToGuest( argv[0], "\"%s\\%s\"" % (self.cwd_guest, argv[1]) ) )

    do_cp = do_vmcopy

    def do_vmget(self, args):
        """
        Get file from vm

        Usage:
            vmget file_of_vm as_file_host
        """
        argv = self.checkargs(args, 2)

        if argv == None: return

        return self.assert_vmrun() and \
            "".join( self.vmrun.copyFileFromGuestToHost( "\"%s\\%s\"" % (self.cwd_guest, argv[0]),
                                                         "%s%s%s" % (self.cwd_host, os.sep, argv[1]) ) )

    do_get = do_vmget

    def do_vmsnap(self, args):
        """Snapshot related commands

        Usage:
            [vm]snap list/create/delete/revert snap-name
        """
        def vmsnap(argv):
            """
            TODO - fix issue of quoted arguments
            Arguments:
            - `*argv`:
            """
            if ( argv[0] == "list" or argv[0] == "l" ):
                print "".join( self.vmrun.listSnapshots() )
            elif ( argv[0] == "create" or
                   argv[0] == "c" ) and argv[1] != "":
                print "".join( self.vmrun.snapshot( argv[1] ) )
            elif ( argv[0] == "delete" or
                   argv[0] == "d" or
                   argv[0] == "del" ) and argv[1] != "":
                print "".join( self.vmrun.deleteSnapshot( argv[1] ) )
            elif ( argv[0] == "revert" or
                   argv[0] == "r" ) and argv[1] != "":
                print "".join( self.vmrun.revertToSnapshot( argv[1] ) )

        argv = self.checkargs(args)

        if argv == []: print "type 'help [vm]snap' ..."; return

        return self.assert_vmrun() and vmsnap(argv)

    do_snap = do_vmsnap

    def do_vmexec(self, args):
        """Execute program in the guest

        Arguments:
        - `self`:
        - `args`:
        """
        def vmexec(argv):
            """

            Arguments:
            - `argv`:
            """
            try:
                pname = argv.pop(0)
                param = " ".join(argv) # FIXME
                # TODO n/a/i
                print "".join( self.vmrun.runProgramInGuest( "\"%s\"" % self.cfg.get( self.section, pname ), "n", "\"%s\"" % param) )
            except Exception, e:
                print "[-] error : %s" % str(e)

        argv = self.checkargs(args)

        if argv == []: print "type 'help [vm]exec' ..."; return

        return self.assert_vmrun() and vmexec(argv)

    do_exec = do_vmexec

    def do_md5(self, args):
        """
        Get file's md5 digest

        Usage:
            md5 file
        """
        argv = self.checkargs(args, 1)

        if argv == None: return

        if not os.path.isfile(argv[0]):
            print "*invalid* file : %s" % argv[0]
            return

        fh = open( argv[0], "rb" )
        m  = hashlib.md5()
        while True:
            data = fh.read(1024)
            if not data: break
            m.update(data)

        print "[MD5] %s : %s" % (argv[0], m.hexdigest())
        fh.close()

    def do_pkinfo(self, args):
        """
        Get pe's packer info

        Usage:
            pkinfo file
        """
        argv = self.checkargs(args, 1)

        if argv == None: return

        fn = argv[0]
        if not os.path.isfile(fn):
            print "*invalid* file : %s" % fn
            return

        pe  = pefile.PE(fn)
        sig = peutils.SignatureDatabase( SIG_FILE )
        pk  = sig.match(pe)
        print "[pkinfo] %s : %s" % (fn, pk)

#-------------------------------------------------------------------------------
if __name__ == '__main__':
    TITLE = '                ...oooOOO Welcome to OOOooo...\n' \
            '      .__ _________                                 .__            \n' \
            '      |__|\_   ___ \   ____    ____    ______ ____  |  |    ____   \n' \
            '      |  |/    \  \/  /  _ \  /    \  /  ___//  _ \ |  |  _/ __ \  \n' \
            '      |  |\     \____(  <_> )|   |  \ \___ \(  <_> )|  |__\  ___/  \n' \
            '      |__| \______  / \____/ |___|  //____  >\____/ |____/ \___  > \n' \
            '                  \/              \/      \/                   \/  \n' \
            '                ...oooOOOOOOOOOOOOOOOOOOooo...'

    opt = optparse.OptionParser( usage="usage: %prog [options]\n" + __description__, version="%prog " + __version__ )
    opt.add_option( "-c", "--config", help="file name of config", default=".config" )
    opt.add_option( "-d", "--debug",  help="out put debug info",  default=False, action="store_true" )

    (opts, args) = opt.parse_args()

    ConsoleUI( "iConsole", TITLE, config=opts.config, debug=opts.debug ).cmdloop()
#-------------------------------------------------------------------------------
# EOF
