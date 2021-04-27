#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import threading
import time 
import thread
import json

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from proposalHeader import GvtProtocol
from receive import *

TYPE_PROP = 0x1919
TYPE_REQ = 0x1515
TYPE_GVT = 0x600
TYPE_DEL = 0x1313
TYPE_PREPARE = 0x3333
TYPE_PREPAREOK = 0x4444
TYPE_STARTCHANGE = 0x4343
TYPE_STARTVIEW = 0x4747
TYPE_FAILURE = 0x5555
TYPE_DELFAILURE = 0x6666
TYPE_VIEWCHANGE = 0x700
TYPE_RESENDPROP = 0x1919

class gvtControl:
    def __init__(self, dest_ip, pid):
        #creates socket to a destination 
        self.addr = socket.gethostbyname(dest_ip)
        self.iface = self.get_if()
        self.pid = pid
        self.dest_ip = dest_ip
        self.GVT_value = 0
        self.last_proposal = 0
        self.last_proposal_time = 0
        self.leader_alive = 1
        self.sent_but_not_yet_acknowledged = 0
        #interfaces

        self.GVT_list = {}
        self.queue = []

        #start receiver thread
        self.receivethread = threading.Thread(target=self.receiveThread)
        self.receivethread.start()

        #just for debugging
        #start run loop
        self.run_loop = threading.Thread(target=self.runThread)
        self.run_loop.start()

        self.send = threading.Thread(target=self.send_queue)
        self.send.start()

        self.list = ["10.0.1.1", "10.0.2.2", "10.0.4.4", "10.0.5.5", "10.0.6.6", 
        "10.0.7.7", "10.0.8.8", "10.0.9.9", "10.0.10.10", "10.0.11.11", "10.0.12.12",
        "10.0.13.13", "10.0.14.14", "10.0.15.15", "10.0.16.16", "10.0.17.17", "10.0.18.18"]

    def receiveThread(self):
        #ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
        #iface = ifaces[0]
        print "sniffing on %s" % self.iface
        sys.stdout.flush()
        sniff(iface = self.iface, prn = lambda x: self.handle_pkt(x))
        #TODO: Change this interface after the failure

    def handle_pkt(self, pkt):
        if TCP in pkt and pkt[TCP].dport == 7777:
            print "got a packet"
            pkt.show2()
            
            self.proposal = json.loads(pkt.load)
            print self.proposal

            self.compute_gvt(self.proposal)
            sys.stdout.flush()


    def compute_gvt(self, proposal):
        key = proposal.keys()
        self.GVT_list[key[0]] = proposal[key[0]]
        minval = min(self.GVT_list.values())
        for x in self.list:
            print('O QUE TACONTECENDO')
            self.send_packet(minval, self.pid, x)


    def resend_old_messages(self):
        #so esta mandando uma mensagem no momento
        #TODO: armazenar e reenviar todas as mensagens da aplicacao
        if(self.sent_but_not_yet_acknowledged):
            self.send_packet(message_value=int(self.sent_but_not_yet_acknowledged), process_pid=self.pid)


    def get_if(self):
        self.ifs=get_if_list()
        iface=None # "h1-eth0"
        for i in get_if_list():
            if "eth0" in i:
                iface=i
                break;
        if not iface:
            print "Cannot find eth0 interface"
            exit(1)
        self.ifs.remove('lo')
        self.ifs.remove('eth0')
        print(self.ifs)
        return iface

    def send_packet(self, message_value, process_pid, p_addr):
        self.payload = {}
        self.payload[process_pid] = message_value 
        pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = 0x800)
        pkt = pkt /IP(dst=p_addr) / TCP(dport=1234, sport=random.randint(49152,65535))/ json.dumps(self.payload)
        sendp(pkt, iface=self.iface, verbose=False)

    def build_proposal(self, proposal_value):
        self.last_proposal = int(proposal_value)
        self.send_packet(message_value=int(proposal_value), process_pid=self.pid)

    #this thread implements a run loop. Just for writing LVT values as a debug functionality 
    def runThread(self):
        while True:
            value = input('Type new LVT:')
            print "sending on interface %s to %s" % (self.iface, str(self.addr))
            #TODO: We need to enforce the concurrency control here
            self.queue.append([value, time.time()])
            #self.last_proposal_time = time.time()

    def send_queue(self):
        #TODO: concurrency control
        while True:
            time.sleep(1)
            if(self.sent_but_not_yet_acknowledged == 0 and len(self.queue) > 0):
                get = self.queue.pop(0)
                self.sent_but_not_yet_acknowledged = get[0]
                print self.sent_but_not_yet_acknowledged
                self.last_proposal_time = get[1]
                self.build_proposal(proposal_value=self.sent_but_not_yet_acknowledged)          

def main():    
    if len(sys.argv)<3:
        #TODO: Does not make sense this Dest IP. Solve it 
        print 'pass 2 arguments: <destination_ip> <pid>'
        exit(1)

    GVTcontrol_instance = gvtControl(sys.argv[1], int(sys.argv[2]))

if __name__ == '__main__':
    main()
