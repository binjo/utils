#!/usr/bin/env python
# -*- coding: utf-8 -*-
# xxx_pdf.py
# Binjo @ 2008-10-10 16:41:08
#-------------------------------------------------------------------------------
import sys, os, zlib, binascii

from pdf_decoder import Decoders

def deflate_pdf( d_or_fh, flag):
    """TODO
    """
#    print "\n-------------[%s]\n" % file

    xx = d_or_fh
    if hasattr( d_or_fh, 'read' ):
        xx = d_or_fh.read()

    if flag == '--hex':
        print "%s" % ''.join(asciihexdecode(xx))
    elif flag == '--85':
        print "%s" % ''.join(ascii85decode(xx))
    else:
#        import pdb
#        pdb.set_trace()
        print "%s" % ''.join(flatedecode(xx))

def ascii85decode(x):
    """decode /ASCII85Decode
    """
    xx = x
    rc = []
    while True:
        yy = []

        pos = xx.find( 'ASCII85Decode' )
        if pos == -1: break                   # still not found, exit

        xx = xx[pos+4:]
        sop = xx.find( 'stream' )
        yy  = xx[sop+6:xx.find('endstream')]

        try:
            if yy[0] == ' ':                 # FIXME found some samples start with a SPACE, does it possible with multi spaces?
                yy = yy[1:]
            # twice check, it can be '\x0D\x0A' or '\x0D' or '\x0A' follow the 'stream'
            if yy[0] == '\r' or yy[0] == '\n':
                yy = yy[1:]
            if yy[0] == '\r' or yy[0] == '\n':
                yy = yy[1:]

            yy = yy[:yy.find('~>')+1]
#            s = ascii85.b85decode(yy)
            d = Decoders()
            s = d.ascii85decode(yy)
            rc.append(s)
        except Exception, e:
            print "[-] shit...%s" % repr(e)
            pass

    return rc

def flatedecode(x):
    """TODO
    """
    xx = x
    rc = []
    while True:
        yy = []

        pos = xx.find( 'FlateDecode' )
        if pos == -1: pos = xx.find( '/Fl' ) # try to find its abbreviate
        if pos == -1: pos = xx.find( '/#46#6c' ) # try to find hexlified stream
        if pos == -1: pos = xx.find( '/F#6c' )
        if pos == -1: pos = xx.find( '/#46l' )
        if pos == -1: break                  # still not found, exit

        xx = xx[pos+4:]
        sop = xx.find( 'stream' )
        yy  = xx[sop+6:xx.find('endstream')]

        try:
            if yy[0] == ' ':                 # FIXME found some samples start with a SPACE, does it possible with multi spaces?
                yy = yy[1:]
            # twice check, it can be '\x0D\x0A' or '\x0D' or '\x0A' follow the 'stream'
            if yy[0] == '\r' or yy[0] == '\n':
                yy = yy[1:]
            if yy[0] == '\r' or yy[0] == '\n':
                yy = yy[1:]

            s = zlib.decompress(yy) + '\n'
            rc.append(s)
        except Exception, e:
            print "[-] shit...%s" % repr(e)
            pass

    return rc

def asciihexdecode(x):
    """TODO
    """
    xx = x
    rc = []
    while True:
        yy = []

        pos = xx.find( 'ASCIIHexDecode' )
        if pos == -1: pos = xx.find( '/AHx' ) # try to find its abbreviate
        if pos == -1: break                   # still not found, exit

        xx = xx[pos+4:]
        sop = xx.find( 'stream' )
        yy  = xx[sop+6:xx.find('endstream')]

        try:
            if yy[0] == ' ':                 # FIXME found some samples start with a SPACE, does it possible with multi spaces?
                yy = yy[1:]
            # twice check, it can be '\x0D\x0A' or '\x0D' or '\x0A' follow the 'stream'
            if yy[0] == '\r' or yy[0] == '\n':
                yy = yy[1:]
            if yy[0] == '\r' or yy[0] == '\n':
                yy = yy[1:]

            yy = yy.replace('\r\n','')
            yy = yy[0:-1]                       # ASCIIHexEncode's tail has a '>'
            s = binascii.unhexlify(yy)
            rc.append(s)
        except:
            pass

    return rc

def main():

    if len(sys.argv) < 3: exit( 'usage: %s -[df] directory | file name -a' % sys.argv[0] )

    flag = ''
    if len(sys.argv) == 4:
        flag = sys.argv[2]

    if sys.argv[1] == '-f':
        fh = open( sys.argv[-1], 'rb' )
        deflate_pdf( fh, flag )
        fh.close()
    elif sys.argv[1] == '-d':
        da = os.listdir( sys.argv[-1] )
        for f in da:
            fh = open( sys.argv[-1] + '\\' + f, 'rb' )
            deflate_pdf( fh, flag )
            fh.close()
    elif sys.argv[1] == '-r' or sys.argv[1] == '--raw':
        deflate_pdf( sys.argv[-1], flag )
    else:
        exit( 'usage: %s -[df] directory | file name' % sys.argv[0] )
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
