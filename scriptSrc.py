import random
import threading

from scapy.all import *
import _thread
import time
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether


class threadSendFast(threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter

    def run(self):
        print("Starting" + self.name)
        p = IP(src="192.168.91.144", dst="192.168.91.145") / TCP(dport=90, flags='S')
        send(p)


class threadSniff(threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter

    def run(self):
        print("Starting" + self.name)
        sniff(prn=process, filter='port 100', store=0)


def process(pkt):
    if pkt[TCP].flags == "SA":
        envoiIp = IP(dst=pkt[IP].src)
        ack = TCP(sport=1500, dport=90, flags="R", seq=random.randint(0, 100), ack=pkt[TCP].seq)
        send(envoiIp / ack)


# parametrage des 3 Threads qui vont être lancé
thread1 = threadSendFast(1, "Thread-1", 1)

# parametrage du thread qui va sniff
thread4 = threadSniff(4, "Thread-4", 4)

# lancement des threads
thread1.start()
thread4.start()
