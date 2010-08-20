#################################################
#
#   Dr. Gadget
#   ----------------------------------------
#   author:     Dennis Elser
#   bugs:       de dot backtrace at dennis
#   version:    0.2
#
#   history:
#   07/24/2010  v0.1 - first public release
#   07/26/2010  v0.1.1 - added copy/cut/paste
#   07/31/2010  v0.2 - with kind permission,
#               added Elias Bachaalany's
#               script to find opcodes/instructions
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
- fix popup menu logic/handler
- clean up ;-)
"""

import idaapi, idc
from idaapi import simplecustviewer_t
import struct, os


pluginname = "Dr. Gadget"

# -----------------------------------------------------------------------

class Gadget:
    
    def __init__ (self):
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
        MakeUnknown (ea, 100, idc.DOUNK_EXPAND)
        AnalyzeArea (ea, ea+100)
        MakeCode (ea)
        return MakeFunction (ea, BADADDR)


    def get_disasm (self, ea):
        next = ea
        gadget = []
        endEA = BADADDR
        inscnt = 0
        # FIXME: stop disassembling at f.endEA ?
        while (next != endEA) or (inscnt < self.maxInsCnt):
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

        
    def load_from_file (self, fileName):
        self.__init__()
        result = False
        f = None
        try:
            f = open (fileName, "rb")
            buf = f.read ()
            self.items = self.get_items_from_buf (buf)
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


    def append_item (self, v):
        self.items.insert (len (self.items), [v, 1])


    def remove_item (self, n):
        self.items.pop (n)

        
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
        if SegStart (val) != BADADDR:
            # TODO: add DEP/ASLR status?
            cline += idaapi.COLSTR ("  ; %s" % SegName (val), idaapi.SCOLOR_AUTOCMT)
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
            
        elif vkey == ord ('O'):
            self.toggle_item ()
            
        elif vkey == ord ('D'):
            self.delete_item ()
                
        elif vkey == ord ("E"):
            self.edit_item ()

        elif vkey == ord ("I"):
            self.insert_item ()

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
            self.menu_reset  = self.AddPopupMenu ("Reset")
            self.AddPopupMenu ("-")
            self.menu_disasm  = self.AddPopupMenu ("Show disassembly")
            
        return True


    def OnPopupMenu (self, menu_id):
        global ph
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
            # TODO: add stack-pointer dependent analysis algorithm :D
            Warning ("Not implemented yet")

            
        elif menu_id == self.menu_reset:
            if idc.AskYN (1, "Are you sure?") == 1:
                ph.reset_type ()
                self.refresh ()

                
        elif menu_id == self.menu_disasm:
            try:
                self.disasm
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
                
        self.refresh ()
        return True


    def refresh (self):
        global ph
        self.ClearLines ()
        code = []
        lastCodePos = 0
        
        for n in xrange (ph.get_number_of_items ()):
            if ph.get_type (n):
                g = Gadget ()
                disasm = g.get_disasm (ph.get_value (n))
                for line in disasm:
                    # FIXME
                    if line.startswith ("ret") and not self.showRet:
                        continue
                    code.append ("   " + idaapi.COLSTR (line, idaapi.SCOLOR_CODNAME))
                    
            elif self.showData:
                val = ph.get_value (n)
                code.append (idaapi.COLSTR ("   %08Xh" % val, idaapi.SCOLOR_DNUM))

        for l in code:
            self.AddLine (l)            
        self.Refresh ()


    def get_switch_setting (self, var):
        return "\7\t" if var else " \t"
        

    def OnPopup (self):
        self.ClearPopupMenu ()
        self.menu_toggledata = self.AddPopupMenu (self.get_switch_setting (self.showData) + "Show data lines") 
        self.menu_toggleret = self.AddPopupMenu (self.get_switch_setting (self.showRet) + "Show return instructions")
        return True


    def OnPopupMenu (self, menu_id):
        if menu_id == self.menu_toggledata:
            self.showData = not self.showData
            self.refresh ()
            
        elif menu_id == self.menu_toggleret:
            self.showRet = not self.showRet
            self.refresh ()
            
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




