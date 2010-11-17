#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
pdf_decoder.py

TODO
"""
__author__  = 'Binjo'
__version__ = '0.1'
__date__    = '2009-07-28 14:56:01'

class Decoders(object):
    """
    """

    def __init__(self, data=None):
        """

        Arguments:
        - `data`:
        """
        self._data = data
        if hasattr( data, 'read' ):
            self._data = data.read()

    def ascii85decode(self, raw=''):
        """decode /ASCII85Decode

        Arguments:
        - `self`:
        - `raw`:
        """
        data = self._data
        if raw != '':
            data = raw

        n = b = 0
        out = ''

        import struct
        for c in data:
            if '!' <= c and c <= 'u':
                n += 1
                b = b*85+(ord(c)-33)
                if n == 5:
                    out += struct.pack('>L',b)
                    n = b = 0
            elif c == 'z':
                assert n == 0
                out += '\0\0\0\0'
            elif c == '~':
                if n:
                    for _ in range(5-n):
                        b = b*85+84
                        out += struct.pack('>L',b)[:n-1]
                    break
        return out

    def asciihexdecode(self, raw=''):
        """decode /ASCIIHexDecode

        Arguments:
        - `self`:
        - `raw`:
        """
        data = self._data
        if raw != '':
            data = raw

        import re
        hex_re = re.compile(r'([a-f\d]{2})', re.IGNORECASE)
        trail_re = re.compile(r'^(?:[a-f\d]{2}|\s)*([a-f\d])[\s>]*$', re.IGNORECASE)
        decode = (lambda hx: chr(int(hx, 16)))
        out = map(decode, hex_re.findall(data))
        m = trail_re.search(data)
        if m:
            out.append(decode("%c0" % m.group(1)))
        return ''.join(out)

    def flatedecode(self, raw=''):
        """decode /FlateDecode

        Arguments:
        - `self`:
        - `raw`:
        """
        data = self._data
        if raw != '':
            data = raw

        import zlib
        return zlib.decompress(data)

def main():
    """TODO
    """
    pass
#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
#-------------------------------------------------------------------------------
# EOF
