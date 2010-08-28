#################################################
#
#   Dr. Gadget
#   ----------------------------------------
#   author:     Dennis Elser
#   bugs:       de dot backtrace at dennis
version      =  "0.3"
#
#   history:
#   07/24/2010  v0.1   - first public release
#   07/26/2010  v0.1.1 - added copy/cut/paste
#   07/31/2010  v0.2   - with kind permission,
#                        added Elias Bachaalany's
#                        script to find opcodes/instructions
#   08/25/2010  v0.3  -  added ARM support
#                        primitive stack/pc tracing for ARM
#                        Disassembly view export to file
#                        string reference scanning in disasm view
#                        add support for comments both in rop view and disasm view in sync
#                        sync offset number diplay between ropview and disasm
#                        by Karthik (neox.fx at gmail dot com)
#
#   known bugs:
#   - disassembly view is not always refreshed
#     correctly
#
##################################################

# have a look at http://hexblog.com/2009/09/assembling_and_finding_instruc.html
# in order to learn how to use the instruction finder

"""
TODOs:
- show DEP/ASLR status?
- implement Auto analysis II?
- symbol tracing for values?
- fix popup menu logic/handler
- clean up ;-)
"""

import idaapi, idc
from idaapi import simplecustviewer_t
import struct, os


pluginname = "Dr.  Gadget " + version


isArm = False;

# -----------------------------------------------------------------------

class Gadget:
    
    def __init__ (self):
        global isArm
        if (isArm):
            self.controlFlowChangers = ["PC}"]
        else:
            self.controlFlowChangers = ["ret", "retn"]
        self.maxInsCnt = 15


    def make_func (self, ea):
        """
        creates a function starting at address ea
        any existing functions/code will be undefined at this address
        """
        funcEA = idaapi.get_func (ea)
        if funcEA:
            DelFunction (funcEA.startEA)
        # FIXME

        if (isArm):
            ea = ea & -2  # make sure it is aligned
            MakeUnknown (ea, self.maxInsCnt, idc.DOUNK_EXPAND)
            for i in range (ea, ea+self.maxInsCnt):
                idc.SetReg(i, "T", 1) # set thumb mode
            AnalyzeArea (ea, ea+self.maxInsCnt)
            return MakeCode (ea)
        else:
            MakeUnknown (ea, 100, idc.DOUNK_EXPAND)
            AnalyzeArea (ea, ea+100)
            MakeCode (ea)
            return MakeFunction (ea, BADADDR)



    def get_disasm (self, ea):
        if (isArm):
            ea = ea & -2  # make sure it is aligned
        next = ea
        gadget = []
        endEA = BADADDR
        inscnt = 0
        # FIXME: stop disassembling at f.endEA ?
        while (next != endEA) and (inscnt < self.maxInsCnt):
            line = GetDisasm (next)        
            gadget.append (line)
            for mnem in self.controlFlowChangers:
                if mnem in line:
                    return gadget
            inscnt += 1
            next = NextHead (next, endEA)
        return gadget

# -----------------------------------------------------------------------

class PayloadHelper:

    def __init__ (self):
        self.items = []
        self.comment = []
        self.size = 0
        self.rawbuf = ""

        
    def load_from_file (self, fileName):
        self.__init__()
        result = False
        f = None
        try:
            f = open (fileName, "rb")
            self.rawbuf = f.read ()
            self.size = len(self.rawbuf)
            self.items = self.get_items_from_buf (self.rawbuf)
            for x in xrange (len(self.items)):
                self.comment.append ("")
            result = True
        except:
            pass
        finally:
            if f:
                f.close ()
        return result


    def save_to_file (self, fileName):
        result = False
        f = None
        try:
            f = open (fileName, "wb")
            buf = self.get_buf_from_items ()
            f.write (buf)
            result = True
        except:
            pass
        finally:
            if f:
                f.close ()
        return result


    def get_buf_from_items (self):
        buf = ""
        for val in self.items:
            buf += struct.pack ("<I", val[0])
        return buf
    

    def get_items_from_buf (self, buf):
        itemlist = []
        for p in xrange (0, len (buf), 4):
            try:
                val = struct.unpack ("<I", buf[p:p+4])[0]
            except:
                break
            itemlist.append ([val, 0])
        return itemlist


    def get_number_of_items (self):
        return len (self.items)


    def get_item (self, n):
        return self.items[n]


    def insert_item (self, n, v):
        self.items.insert (n, [v, 0])
        self.comment.insert (n, "")


    def append_item (self, v):
        self.items.insert (len (self.items), [v, 1])
        self.comment.insert (len (self.comment), "")


    def remove_item (self, n):
        self.items.pop (n)
        self.comment.pop (n)

        
    def get_value (self, n):
        return self.items[n][0]


    def set_value (self, n, v):
        self.items[n][0] = v


    def get_type (self, n):
        return self.items[n][1]


    def set_type (self, n, v):
        self.items[n][1] = v


    def analyze (self):
        for n in xrange (self.get_number_of_items ()):
            ea = self.get_value (n)
            if SegStart (ea) != BADADDR:
                typ = 1
                g = Gadget ()
                if not g.make_func (ea):
                    print "%08X: failed" % ea
            else:
                typ = 0
            self.set_type (n, typ)


    def traceArmPC (self):
        nl = self.get_number_of_items ()
        n = 0
        lasttype1 = 0
        gap = False
        while n < nl:
            r2 = 1
            ea = self.get_value (n)
            if SegStart (ea) != BADADDR:
                typ = 1
                g = Gadget ()
                if not g.make_func (ea):
                    print "%08X: failed" % ea
                asm = g.get_disasm(ea)
                if (asm[-1].startswith("POP") and asm[-1].endswith(",PC}")):
                    l = asm[-1]
                    rt = (l.split('{'))[1]
                    rtc = rt.split(',')
                    if len(rtc) == 2 and rtc[0].find('-') > 0:
                        rtch = rtc[0].split('-')
                        t = int(rtch[1][1]) - int(rtch[0][1]) + 1
                    else:
                        t = len(rtc)-1
                    if ((n+t) < nl):
                        r2 = t
                    else:
                        r2 = nl-n-1
                    for i in xrange (r2):
                        self.set_type (n+i+1, 0)
                    r2 = r2 + 1
                    if lasttype1:
                        if (n-lasttype1)>15:
                            print "too much ROP gap before EA, probably not a Gadget: %x" % ea
                            typ = 0
                            gap = True
                        elif gap:
                            print "new ROP sequence start at EA: %x?" % ea
                            gap = False
                            self.set_type(lasttype1, 1)
                        lasttype1 = n
                else:
                    print "unexpected end EA, probably not a Gadget: %x" % ea
                    typ = 0
            else:
                typ = 0
            self.set_type (n, typ)
            if typ:
                lasttype1 = n
            n = n + r2


    def reset_type (self):
        for n in xrange (self.get_number_of_items ()):
            self.set_type (n, 0)


    def get_colored_line (self, n):
        # todo
        typ = self.get_type (n)
        cline = idaapi.COLSTR("%03X  " % (n*4), idaapi.SCOLOR_AUTOCMT)
        val = self.get_value (n)
        elem = "%08X" % val
        if typ:
            elem = idaapi.COLSTR(elem, idaapi.SCOLOR_CODNAME)
        else:
            elem = idaapi.COLSTR(elem, idaapi.SCOLOR_DNUM)
        cline += elem
        comm = ""
        if SegStart (val) != BADADDR:
            # TODO: add DEP/ASLR status?
            comm = "  ; %s %s" % (SegName (val), self.comment[n])
        elif self.comment[n] != "":
            comm = "  ; %s" % self.comment[n]
        cline += idaapi.COLSTR (comm, idaapi.SCOLOR_AUTOCMT)
        return cline


    def get_colored_lines (self):
        lines = []
        for i in xrange (self.get_number_of_items ()):
            l = self.get_colored_line (i)
            lines.append (l)
        return lines



# -----------------------------------------------------------------------   

# TODO: remove load- and save payload dialogs from context menu
# and move to IDA's File menu?
class ropviewer_t (simplecustviewer_t):

  
    def Create (self):
        global ph
        
        # FIXME: ugly
        self.menu_loadfromfile  = None
        self.menu_savetofile    = None
        self.menu_copyitem      = None
        self.menu_cutitem       = None
        self.menu_pasteitem     = None
        self.menu_insertitem    = None
        self.menu_jumpto        = None
        self.menu_toggle        = None
        self.menu_deleteitem    = None
        self.menu_edititem      = None
        self.menu_reset         = None
        self.menu_autorec       = None
        self.menu_autorec2      = None
        self.menu_disasm        = None
        self.menu_findinsn      = None

        self.item_clipboard     = None
        
        if not simplecustviewer_t.Create (self, pluginname + " - payload"):
            return False
        if ph:
            self.refresh ()
        else:
            self.ClearLines ()
        return True


    def copy_item (self):
        global ph
        if ph.get_number_of_items ():
            n = self.GetLineNo ()
            self.item_clipboard = (n, "c", ph.get_item (n))


    def paste_item (self):
        global ph
        if self.item_clipboard and ph.get_number_of_items ():
            n = self.GetLineNo ()
            _n, mode, item = self.item_clipboard
            ph.insert_item (n, item[0])
            ph.set_type (n, item[1])
            self.refresh ()
            if mode == 'x':
                self.item_clipboard = None


    def cut_item (self):
        global ph
        if ph.get_number_of_items ():
            n = self.GetLineNo ()
            self.item_clipboard = (n, "x", ph.get_item (n))
            self.delete_item (False)


    def insert_item (self):
        global ph
        n = self.GetLineNo () if self.Count () else 0
        ph.insert_item (n, 0)
        self.refresh ()


    def edit_item (self):
        global ph
        if ph.get_number_of_items ():
            n = self.GetLineNo ()
            val = ph.get_value (n)
            newVal = AskAddr (val, "Enter new value")
            if newVal:
                ph.set_value (n, newVal)
                self.refresh ()


    def delete_item (self, ask = True):
        global ph
        if ph.get_number_of_items ():
            result = 1
            if ask:
                result = AskYN (0, "Delete item?")
            if result == 1:
                ph.remove_item (self.GetLineNo ())
                self.refresh ()


    def addcomment (self, n):
        global ph
        if n < ph.get_number_of_items ():
            s = AskStr (ph.comment[n], "Enter Comment")
            if s:
                ph.comment[n] = s
            self.refresh ()

               
    def toggle_item (self):
        global ph
        if ph.get_number_of_items ():
            n = self.GetLineNo ()

            if ph.get_type (n):
                ph.set_type (n, 0)
            else:
                ea = ph.get_value (n)
                ph.set_type (n, 1)
                g = Gadget ()
                g.make_func (ea)

            l = ph.get_colored_line (n)
            self.EditLine (n, l)
            self.RefreshCurrent ()        


    def refresh (self):
        global ph
        self.ClearLines ()
        for line in ph.get_colored_lines ():
            self.AddLine (line)
        self.Refresh ()


    def OnDblClick (self, shift):
        global ph
        n = self.GetLineNo ()
        Jump (ph.get_value (n))
        return True


    def OnKeydown (self, vkey, shift):
        global ph
        # escape
        if vkey == 27:
            self.Close ()

        # enter
        elif vkey == 13:
            n = self.GetLineNo ()
            Jump (ph.get_value (n))
            
        # always put multiple key conditions first
        elif shift == 4 and vkey == ord ("C"):
            self.copy_item ()

        elif shift == 4 and vkey == ord ("X"):
            self.cut_item ()

        elif shift == 4 and vkey == ord ("V"):
            self.paste_item()

        elif shift == 4 and vkey == ord ("F"):
            s = AskStr ("", "Find instruction(s)")
            if s:
                find (s, False)

        elif vkey == ord ('O'):
            self.toggle_item ()
            
        elif vkey == ord ('D'):
            self.delete_item ()
                
        elif vkey == ord ("E"):
            self.edit_item ()

        elif vkey == ord ("I"):
            self.insert_item ()

        elif vkey == ord ("R"):
            self.refresh ()

        elif vkey == ord ("C"):
            self.addcomment (self.GetLineNo ())

        else:
            return False
        
        return True


    def OnHint (self, lineno):
        global ph
        if not ph.get_type (lineno):
            return None
        
        ea = ph.get_value (lineno)
        g = Gadget ()
        dis = g.get_disasm (ea)
        hint = ""
        for l in dis:
            hint += idaapi.COLSTR ("%s\n" % l, idaapi.SCOLOR_CODNAME)
            
        return (len (dis), hint)


    def OnPopup (self):
        global ph
        global isArm
        self.ClearPopupMenu ()

        # FIXME: ugly
        if not self.Count ():
            self.menu_loadfromfile = self.AddPopupMenu ("Load payload")
            self.AddPopupMenu ("-")
            self.menu_findinsn = self.AddPopupMenu ("Find instruction(s)")
            self.menu_insertitem = self.AddPopupMenu ("Insert item")
        
        else:
            self.menu_loadfromfile = self.AddPopupMenu ("Load payload")
            self.menu_savetofile = self.AddPopupMenu ("Save payload")
            self.AddPopupMenu ("-")
            self.menu_jumpto = self.AddPopupMenu ("Jump to item address")
            self.menu_toggle = self.AddPopupMenu ("Toggle item type")
            self.menu_edititem = self.AddPopupMenu ("Edit item value")
            self.AddPopupMenu ("-")
            self.menu_findinsn = self.AddPopupMenu ("Find instruction(s)")
            self.menu_insertitem = self.AddPopupMenu ("Insert item")
            self.menu_deleteitem = self.AddPopupMenu ("Delete item")
            self.menu_cutitem = self.AddPopupMenu ("Cut item")
            self.menu_copyitem = self.AddPopupMenu ("Copy item")
            self.menu_pasteitem = self.AddPopupMenu ("Paste item")
            self.AddPopupMenu ("-")        
            self.menu_autorec = self.AddPopupMenu ("Auto analysis I")
            self.menu_autorec2 = self.AddPopupMenu ("Auto analysis II")
            if isArm:
                self.menu_armPCtrace = self.AddPopupMenu ("ARM PC trace")
            self.menu_reset  = self.AddPopupMenu ("Reset")
            self.AddPopupMenu ("-")
            self.menu_disasm  = self.AddPopupMenu ("Show disassembly")
            
        return True


    def OnPopupMenu (self, menu_id):
        global ph
        global isArm
        if menu_id == self.menu_loadfromfile:
            fileName = idc.AskFile (0, "*.*", "Import ROP binary")
            if fileName and ph.load_from_file (fileName):
                self.refresh ()

        elif menu_id == self.menu_savetofile:
            fileName = idc.AskFile (1, "*.*", "Export ROP binary")
            if fileName and ph.save_to_file (fileName):
                print "payload saved to %s" % fileName

                        
        elif menu_id == self.menu_jumpto:
            n = self.GetLineNo ()
            Jump (ph.get_value (n))

            
        elif menu_id == self.menu_autorec:
            ph.analyze ()
            self.refresh ()

                
        elif menu_id == self.menu_autorec2:
            # TODO: add stack-pointer dependent analysis algorithm for x86 :D
            Warning ("Not implemented yet")


        elif isArm and menu_id == self.menu_armPCtrace:
            ph.traceArmPC ()
            self.refresh ()

            
        elif menu_id == self.menu_reset:
            if idc.AskYN (1, "Are you sure?") == 1:
                ph.reset_type ()
                self.refresh ()


        elif menu_id == self.menu_disasm:
            try:
                self.disasm
                self.disasm.refresh ()
                self.disasm.Show ()
                
            except:
                self.disasm = disasmviewer_t ()
                if self.disasm.Create ():
                    self.disasm.Show ()
                else:
                    del self.disasm
               
                    
        elif menu_id == self.menu_toggle:
            self.toggle_item ()

        elif menu_id == self.menu_deleteitem:
            self.delete_item ()

        elif menu_id == self.menu_insertitem:
            self.insert_item ()

        elif menu_id == self.menu_edititem:
            self.edit_item ()

        elif menu_id == self.menu_copyitem:
            self.copy_item ()

        elif menu_id == self.menu_cutitem:
            self.cut_item ()

        elif menu_id == self.menu_pasteitem:
            self.paste_item ()

        elif menu_id == self.menu_findinsn:
            s = AskStr ("", "Find instruction(s)")
            if s:
                find (s, False)            
            
        else:
            return False
        
        return True

# -----------------------------------------------------------------------

class disasmviewer_t (simplecustviewer_t):
    
    def Create (self):
        if not simplecustviewer_t.Create (self, pluginname + " - disassembly"):
            return False

        self.showData   = True
        self.showRet    = True
        self.popStrings = False
        self.strBase    = 0

        self.code = []
        self.codetext = []
        self.disasmToRopviewerLine = {}

        self.refresh ()
        return True


    def refresh (self):
        global ph
        self.ClearLines ()
        self.codetext = []
        self.code = []
        self.disasmToRopviewerLine = {}
        lnmapper = 0
        for n in xrange (ph.get_number_of_items ()):
            self.disasmToRopviewerLine[lnmapper] = n
            cln = idaapi.COLSTR("%04X " % (n*4), idaapi.SCOLOR_AUTOCMT)
            comm = ""
            if ph.comment[n] != "":
                comm = "  ; %s" % ph.comment[n]
            c_comm = idaapi.COLSTR (comm, idaapi.SCOLOR_AUTOCMT)

            if ph.get_type (n):
                g = Gadget ()
                disasm = g.get_disasm (ph.get_value (n))
                dtog = False
                for line in disasm:
                    if line.startswith ("ret") and not self.showRet:
                        continue
                    if not dtog:  # add comment only once in a multiline instr seq
                        self.code.append ("  \t " + idaapi.COLSTR (line, idaapi.SCOLOR_CODNAME) + c_comm)
                        self.codetext.append ("  \t " + line + comm + "\n")
                        dtog = True
                    else:
                        self.code.append ("  \t " + idaapi.COLSTR (line, idaapi.SCOLOR_CODNAME))
                        self.codetext.append ("  \t " + line + "\n")
                        lnmapper = lnmapper + 1
                        self.disasmToRopviewerLine[lnmapper] = n
                    
            elif self.showData:
                val = ph.get_value (n)
                if not self.popStrings:
                    self.code.append (cln + idaapi.COLSTR ("    %08Xh" % val, idaapi.SCOLOR_DNUM) + c_comm)
                    self.codetext.append (("%04X    %08Xh%s" % (n*4, val, comm)) + "\n")
                else:
                    if (val > self.strBase) and ((val-self.strBase) < ph.size):
                        off = val - self.strBase
                        ch1 = ord(ph.rawbuf[off:off+1])
                        if (ch1 >= 0x20 and ch1 < 0x7f):
                            eos = ph.rawbuf[off:].find(chr(0))
                            trailer = ""
                            if eos > 0:
                                if (eos > 50):
                                    eos = 50
                                    trailer = "..."
                                strtext = "    --> \"%s\"" % ph.rawbuf[off:off+eos] + trailer
                            else:
                                strtext = ""
                        else:
                            strtext = ""
                        self.code.append (cln + idaapi.COLSTR ("    %08Xh" % val, idaapi.SCOLOR_DNUM) + idaapi.COLSTR ("%s" % strtext, idaapi.SCOLOR_STRING) + c_comm)
                        self.codetext.append (("%04X    %08Xh%s%s" % (n*4, val, strtext, comm)) + "\n")
                    else:
                        self.code.append (cln + idaapi.COLSTR ("    %08Xh" % val, idaapi.SCOLOR_DNUM) + c_comm)
                        self.codetext.append (("%04X    %08Xh%s" % (n*4, val, comm)) + "\n")
            lnmapper = lnmapper + 1

        for l in self.code:
            self.AddLine (l)            
        self.Refresh ()


    def save_to_file (self, filename):
        result = False
        f = None
        try:
            f = open (filename, "w+")
            for l in self.codetext:
                f.write (l)
            result = True
        except Exception, err:
            print "[!] An error occurred:", err
        finally:
            if f:
                f.close ()
        return result


    def addcomment (self, n):
        global ph
        global rv
        nlo = self.disasmToRopviewerLine[n]
        if nlo < ph.get_number_of_items ():
            s = AskStr (ph.comment[nlo], "Enter Comment")
            if s:
                ph.comment[nlo] = s
            self.refresh ()
            rv.refresh ()


    def get_switch_setting (self, var):
        return "\7\t" if var else " \t"
        

    def OnKeydown (self, vkey, shift):
        global ph

        if vkey == ord ("C"):
            self.addcomment (self.GetLineNo ())
            self.Refresh ()         

        elif vkey == ord ("R"):
            self.refresh ()

        else:
            return False
        
        return True


    def OnPopup (self):
        self.ClearPopupMenu ()
        self.menu_toggledata = self.AddPopupMenu (self.get_switch_setting (self.showData) + "Show data lines") 
        if not isArm:
            self.menu_toggleret = self.AddPopupMenu (self.get_switch_setting (self.showRet) + "Show return instructions")
        else:
            self.menu_toggleret = None
        self.menu_populatestrings = self.AddPopupMenu (self.get_switch_setting (self.popStrings) + "Show strings referenced")
        self.menu_savetofile = self.AddPopupMenu ("Save Disasembly")
        return True


    def OnPopupMenu (self, menu_id):
        if menu_id == self.menu_toggledata:
            self.showData = not self.showData
            self.refresh ()
            
        elif menu_id == self.menu_toggleret:
            self.showRet = not self.showRet
            self.refresh ()

        elif menu_id == self.menu_populatestrings:
            self.popStrings = not self.popStrings
            if self.popStrings:
                self.strBase = idc.AskLong(self.strBase, "Base displacement to use?")
            self.refresh ()

        elif menu_id == self.menu_savetofile:
            fileName = idc.AskFile (1, "*.*", "Export ROP Disasembly view")
            if fileName and self.save_to_file (fileName):
                print "disasm saved to %s" % fileName
            
        else:
            return False
        
        return True

# the following code is taken from
# http://hexblog.com/2009/09/assembling_and_finding_instruc.html
# -----------------------------------------------------------------------
def FindInstructions(instr, asm_where=None):
    """
    Finds instructions/opcodes
    @return: Returns a tuple(True, [ ea, ... ]) or a tuple(False, "error message")
    """
    if not asm_where:
        # get first segment
        asm_where = FirstSeg()
        if asm_where == idaapi.BADADDR:
            return (False, "No segments defined")

    # regular expression to distinguish between opcodes and instructions
    re_opcode = re.compile('^[0-9a-f]{2} *', re.I)

    # split lines
    lines = instr.split(";")

    # all the assembled buffers (for each instruction)
    bufs = []
    for line in lines:
        if re_opcode.match(line):
            # convert from hex string to a character list then join the list to form one string
            buf = ''.join([chr(int(x, 16)) for x in line.split()])
        else:
            # assemble the instruction
            ret, buf = Assemble(asm_where, line)
            if not ret:
                return (False, "Failed to assemble:"+line)
        # add the assembled buffer
        bufs.append(buf)

    # join the buffer into one string
    buf = ''.join(bufs)
    
    # take total assembled instructions length
    tlen = len(buf)

    # convert from binary string to space separated hex string
    bin_str = ' '.join(["%02X" % ord(x) for x in buf])

    # find all binary strings
    print "Searching for: [%s]" % bin_str
    ea = MinEA()
    ret = []
    while True:
        ea = FindBinary(ea, SEARCH_DOWN, bin_str)
        if ea == idaapi.BADADDR:
            break
        ret.append(ea)
        Message(".")
        ea += tlen
    if not ret:
        return (False, "Could not match [%s]" % bin_str)
    Message("\n")
    return (True, ret)

# -----------------------------------------------------------------------
# Chooser class
class SearchResultChoose(Choose2):
    def __init__(self, list, title):
        self.list = list
        Choose2.__init__(self, \
                         title, \
                         [["address", 10 | Choose2.CHCOL_PLAIN], \
                          ["segment", 10 | Choose2.CHCOL_PLAIN], \
                          ["code", 30 | Choose2.CHCOL_PLAIN]], \
                         popup_names = ["Insert", "Delete", "Edit", "Append to payload"])

    def OnRefresh(self, n):
        global ph
        global rv
        print "appending %08X to payload" % self.list[n-1].ea
        ph.append_item (self.list[n-1].ea)
        rv.refresh ()
        return len(self.list)

    def OnClose (self):
        pass

    def OnGetLine (self, n):
        return self.list[n-1].columns

    def OnGetSize (self):
        return len (self.list)

    def OnSelectLine(self, n):
        Jump (self.list[n-1].ea)
    

# -----------------------------------------------------------------------
# class to represent the results
class SearchResult:
    def __init__(self, ea):
        self.ea = ea
        self.columns = []
        if not isCode(GetFlags(ea)):
            MakeCode(ea)
        t = idaapi.generate_disasm_line(ea)
        if t:
            line = idaapi.tag_remove(t)
        else:
            line = ""
        self.columns.append ("%08X" % ea)
        n = SegName(ea)
        self.columns.append (n)
        self.columns.append (line)

# -----------------------------------------------------------------------
def find(s=None, x=False, asm_where=None):
    b, ret = FindInstructions(s, asm_where)
    if b:
        # executable segs only?
        if x:
            results = []
            for ea in ret:
                seg = idaapi.getseg(ea)
                if (not seg) or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
                    continue
                results.append(SearchResult(ea))
        else:
            results = [SearchResult(ea) for ea in ret]
        title = "Search result for: [%s]" % s
        idaapi.close_chooser(title)
        c = SearchResultChoose(results, title)
        c.Show()
    else:
        print ret

# -----------------------------------------------------------------------
def get_processor_name():
    inf = idaapi.get_inf_structure()
    eos = inf.procName.find(chr(0))
    if eos > 0:
        return inf.procName[:eos]
    else:
        return inf.procName


# -----------------------------------------------------------------------

ph = None
rv = None

class dgplugin_t (idaapi.plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = pluginname
    wanted_hotkey = "Alt-F5"

    def init (self):
        global rv
        rv = None
        return idaapi.PLUGIN_OK


    def run (self, arg):
        global ph
        global rv
        global isArm
        if (get_processor_name() == 'ARM'):
            isArm = True
        if not ph:
            ph = PayloadHelper ()
        if not rv:
            rv = ropviewer_t ()
            if not rv.Create ():
                print "could not create window."
                return
        rv.Show ()
            
    def term (self):
        pass

# -----------------------------------------------------------------------

def PLUGIN_ENTRY ():
    return dgplugin_t ()      




