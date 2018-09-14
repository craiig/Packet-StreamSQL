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

from pyspark.sql import SparkSession
from pyspark.sql.functions import explode
from pyspark.sql.functions import split

DPORT = 0x0da2


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', DPORT))
    while True:
        tupl, clientAddress = s.recvfrom(200)
        # tupl = struct.unpack('>III10s',tupl)
        # tupl = struct.unpack('>I10s',tupl)
        tupl = struct.unpack('>III10sI',tupl)
        print str(tupl), str(clientAddress)

if __name__ == '__main__':
    main()


# def main():
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.bind(('', DPORT))
#     s.listen(1)
#     while True:
#     	c = s.accept()
#         tupl = c[0].recv(200)
#         # tupl = struct.unpack('>III10s',tupl)
#         # tupl = struct.unpack('>I10s',tupl)
#         tupl = struct.unpack('>I10sI',tupl)
#         print str(tupl)
#         c[0].close()


# sudo echo "JAVA_HOME=/usr" >> /etc/environment
# source /etc/environment

# def main():
#     spark = SparkSession \
#         .builder \
#         .appName("TupleFiltering") \
#         .getOrCreate()

#     socketDF = spark \
#         .readStream \
#         .format("socket") \
#         .option("host", "localhost") \
#         .option("port", 3490) \
#         .load()

#     ans = socketDF.select()

#     query = ans \
#     		.writeStream \
#     		.format("console") \
#     		.start()

#     query.awaitTermination()

#     # socketDF.isStreaming()    # Returns True for DataFrames that have streaming sources
#     # socketDF.printSchema()

# if __name__ == '__main__':
#     main()


