#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import threading

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from proposalHeader import GvtProtocol
from receive import *

TYPE_PROP = 0x1919
TYPE_REQ = 0x1515
TYPE_GVT = 0x666
TYPE_DEL = 0x1313
TYPE_PREPARE = 0x3333;
TYPE_PREPAREOK = 0x4444;


class gvtControl:

    def __init__(self, dest_ip, pid):
        #creates socket to a destination 
        self.addr = socket.gethostbyname(dest_ip)
        self.iface = get_if()
        self.pid = pid
        self.round = 0
        self.dest_ip = dest_ip
        self.GVT_value = 0
        self.last_proposal = 0;

        #start receiver thread
        self.receivethread = threading.Thread(target=self.receiveThread)
        self.receivethread.start()
        #start run loop
        self.run_loop = threading.Thread(target=self.runThread)
        self.run_loop.start()


    def receiveThread(self):
        ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
        iface = ifaces[0]
        print "sniffing on %s" % iface
        sys.stdout.flush()
        sniff(iface = iface, prn = lambda x: self.handle_pkt(x))

    def handle_pkt(self, pkt):
        if TCP in pkt and pkt[TCP].dport == 1234:
           print "got a packet"
        #pkt.show2()
        if GvtProtocol in pkt:
            if pkt[GvtProtocol].flag == TYPE_PREPARE:
                self.send_packet(flag_operation=TYPE_PREPAREOK, message_value=self.last_proposal, process_pid=self.pid, round_number=self.round)
            elif pkt[GvtProtocol].flag == TYPE_DEL:
                self.GVT_value = pkt[GvtProtocol].value
                self.round = pkt[GvtProtocol].round
                print "got new value: " + str(self.GVT_value)

        sys.stdout.flush()

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


    def send_packet(self, flag_operation, message_value, process_pid, round_number):
        pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = TYPE_GVT)
        pkt = pkt / GvtProtocol(flag = flag_operation, value=message_value, pid = process_pid, round=round_number)
        pkt = pkt /IP(dst=self.addr) / TCP(dport=1234, sport=random.randint(49152,65535))
        pkt.show2()
        sendp(pkt, iface=self.iface, verbose=False)


    #this thread implements a run loop. Just for writing LVT values 
    def runThread(self):
        while True:
            x = input('Type new LVT:')
            print "sending on interface %s to %s" % (self.iface, str(self.addr))
            #TODO: We need to enforce the concurrency control here
            self.last_proposal = int(x)
            self.send_packet(flag_operation=TYPE_PROP, message_value=int(x), process_pid=self.pid, round_number=self.round)

def main():
    
    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination_ip> <pid>'
        exit(1)

    GVTcontrol_instance = gvtControl(sys.argv[1], int(sys.argv[2]))

    #thread to receive new GVT values    

    #while True:
    #    x = input('Type new LVT:')
    #    print "sending on interface %s to %s" % (iface, str(addr))
    #    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type = TYPE_GVT)
    #    pkt = pkt / GvtProtocol(flag = TYPE_PROP, value=int(x), pid = int(sys.argv[2]), round=1)
    #    pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535))
    #    pkt.show2()
    #    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
