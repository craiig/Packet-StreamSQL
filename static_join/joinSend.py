#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import re
import readline
import numpy as np
import time

from scapy.all import sendp, send, srp1, get_if_list, get_if_hwaddr
from scapy.all import Packet, hexdump
from scapy.all import Ether, IP, UDP, ShortField, StrFixedLenField, XByteField, IntField
from scapy.all import bind_layers
from scapy.config import conf

DPORT = 0x0da2


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def main():

    if len(sys.argv)<2:
        print 'pass 1 argument: <destination IP>'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print "sending on interface %s to %s" % (iface, str(addr))
    tuples = np.random.randint(100, size=(10000, 3))
    strings = ['vikas', 'john', 'alice', 'joan', 'diane', 'matt', 'bob', 'tom']
    # tuples = [[27,12,13]]
    # strings = ['vikas']

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    count = 0
    for t in tuples: 
        try:
            string = random.choice(strings)
            data = struct.pack('>III10s', t[0],t[1],t[2], string)
    	    s.sendto(data, (addr, DPORT))
            count = count + 1
            time.sleep(0.01)
            print( t[0], t[1], t[2], string), count

        except Exception as error:
            print error


if __name__ == '__main__':
    main()

# def main():

#     if len(sys.argv)<2:
#         print 'pass 1 argument: <destination IP>'
#         exit(1)

#     addr = socket.gethostbyname(sys.argv[1])
#     iface = get_if()
#     print "sending on interface %s to %s" % (iface, str(addr))
#     # tuples = np.random.randint(100, size=(1000, 3))
#     # strings = ['vikas', 'john', 'alice', 'joan', 'diane', 'matt', 'bob', 'tom']

#     tuples = [[27,12,13]]
#     strings = ['alice']

#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.connect((addr, DPORT))
#     count = 0
#     for t in tuples: 
#         try:
#             string = random.choice(strings)
#             data = struct.pack('>III10s', t[0],t[1],t[2], string)
#             s.sendall(data)
#             count = count + 1
#             time.sleep(0.01)
#             print( t[0], t[1], t[2], string), count

#         except Exception as error:
#             print error
#     s.close()


#         print 'pass 2 arguments: <destination>'
#         exit(1)

#     addr = socket.gethostbyname(sys.argv[1])
#     iface = get_if()
#     print "sending on interface %s to %s" % (iface, str(addr))

#     tuples = np.random.randint(100, size=(10000, 3))
#     valid = 0
#     dropped = 0

#     s = conf.L2socket(iface=iface)
#     s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#     for t in tuples: 
#         try:
#             data=struct.pack("iii", 27, 35, 65)
#             # sendp(pkt, iface=iface, verbose=False)
#             s.sendto(data, ("10.0.2.2", 3490))

#         except Exception as error:
#             print error


# if __name__ == '__main__':
#     main()


