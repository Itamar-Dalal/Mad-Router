from scapy.all import *


IFACE_1 = "enp0s8"
SUBNET_1 = "192.168.1"

IFACE_2 = "enp0s9"
SUBNET_2 = "192.168.2"

PROXY_IP = "192.168.2.2"
ALICE_IP = "192.168.1.1"

routing_table = {} # subnet -> iface
routing_table[SUBNET_1] = IFACE_1
routing_table[SUBNET_2] = IFACE_2


def modify_packet(pkt):
    # check if Alice is not connecting to proxy
    # if not, then change the src ip to proxy's ip
    if pkt.sniffed_on == IFACE_1 and pkt[IP].dst != PROXY_IP:
        pkt[IP].src = PROXY_IP

    # change the dst ip back to alice's ip
    if pkt.sniffed_on == IFACE_2 and pkt[IP].dst == PROXY_IP:
        pkt[IP].dst = ALICE_IP

    return pkt


def route(pkt):
    # modify proxy changes before route
    pkt = modify_packet(pkt)
    
    for subnet in routing_table.keys():
        if subnet in pkt[IP].dst:
            # get only ingoing packets
            if pkt.sniffed_on != routing_table[subnet]:
                sendp(pkt, routing_table[subnet])


def main():
    sniff(iface=[IFACE_1, IFACE_2], prn=route, filter="ip")


if __name__ == "__main__":
    main()
