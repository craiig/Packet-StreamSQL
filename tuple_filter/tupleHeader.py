from scapy.all import *
import sys, os

DPORT = 0x0da2
# MY_AGE = 0x0000001b; // 27

class Tuple(Packet):
    name = "Tuple"
    fields_desc = [ 
                    IntField("age", 0),
                    IntField("height", 0),
                    IntField("weight", 0)]

bind_layers(UDP, Tuple, dport=DPORT)


