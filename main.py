from scapy.all import *


IFACE_1 = "enp0s8"
SUBNET_1 = "192.168.1"

IFACE_2 = "enp0s9"
SUBNET_2 = "192.168.2"


routing_table = {} # subnet -> iface
routing_table[SUBNET_1] = IFACE_1
routing_table[SUBNET_2] = IFACE_2


def route(pkt):
    dst_ip = pkt[IP].dst
    for subnet in routing_table.keys():
        if subnet in dst_ip:
            if pkt.sniffed_on != routing_table[subnet]:
                sendp(pkt, routing_table[subnet])


def main():
    sniff(iface=[IFACE_1, IFACE_2], prn=route, filter="ip")


if __name__ == "__main__":
    main()
