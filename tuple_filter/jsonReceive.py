#!/usr/bin/env python
import sys
import struct
import os
import socket

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from tupleHeader import Tuple

from pyspark.sql import SparkSession
from pyspark.sql.functions import explode
from pyspark.sql.functions import split

DPORT = 0x1F40


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', DPORT))
    while True:
        tupl, clientAddress = s.recvfrom(200)
        # tupl = struct.unpack('>III10s',tupl)
        # tupl = struct.unpack('>I10s',tupl)
        # tupl = struct.unpack('>I10sI',tupl)
        print str(tupl)

if __name__ == '__main__':
    main()