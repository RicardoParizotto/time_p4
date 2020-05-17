from scapy.all import *
import sys, os

class GvtProtocol(Packet):
     fields_desc = [   IntField("type", 0),
					IntField("pid", 0),
                                        IntField("lvt", 0),
				        IntField("round", 0)]