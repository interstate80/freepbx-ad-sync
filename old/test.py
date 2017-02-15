#! /usr/bin/python
# -*- coding: utf-8 -*-

import os, re, sys


def macser(ttl):
    out = os.popen('grep -R %s /var/lib/tftpboot/' % ttl)
    st = out.readline()
    out.close()

    if st:
        a = st.replace('/var/lib/tftpboot/', '')
        spatt = '([0-9a-z]+\.cfg)'
        b = re.search(spatt, a)
        return b.group(0).replace('.cfg', '')
    else:
        return False
    
if __name__ == '__main__':
    for param in sys.argv:
        a = macser(param)
        if a and a == '001122334455':
            print("%s -> %s" % (param, a))