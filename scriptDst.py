from scapy.all import *
import hashlib
from random import randint

from scapy.layers.inet import IP, TCP

SERIAL_UUID = '123456'


def process_packet(pkt):
    if pkt[TCP].flags == "S":
        myCookie = generateHash(pkt)

        # Preparation de l'envoi
        envoiIp = IP(dst=pkt[IP].src)
        ack = TCP(sport=1500, dport=100, flags="SA", seq=myCookie, ack=pkt[TCP].seq + 1)
        send(envoiIp / ack)

    if pkt[TCP].flags == "R":
        myCookie = generateHash(pkt)
        if pkt[TCP].seq == myCookie:
            file_object = open('whitelist.txt', 'a')
            file_object.write(pkt[TCP].src)
            file_object.close()


def generateHash(pkt):
    hashPkt = str((str(pkt[IP].src) + str(pkt[TCP].sport) + str(pkt[IP].dst) + str(pkt[TCP].dport)
                   + SERIAL_UUID).encode('utf-8'))
    return int(hashlib.sha1(hashPkt.encode("utf-8")).hexdigest(), 16) % (10 ** 9)


# On lance d'abord les sniff
myfilter = 'port 90 and tcp'
captureSniff = sniff(prn=process_packet, filter=myfilter, store=0)
