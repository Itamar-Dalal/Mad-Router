from scapy.all import *
import ipaddress
from random import randrange


# IN INTERFACE
IFACE_IN = "enp0s8"
SUBNET_IN = "192.168.1"

# OUT INTERFACE
IFACE_OUT = "enp0s9"
SUBNET_OUT = "192.168.2"

# NAT
NAT_IP = "192.168.2.2"

# ROUTING TABLE
routing_table = {} # subnet -> iface
routing_table[SUBNET_IN] = IFACE_IN
routing_table[SUBNET_OUT] = IFACE_OUT

# NAT TABLE
nat_table = {} # router's out port -> (client's ip, client's in port) or identifer -> ip,identifier in icmp


routing_table = {} # subnet -> iface
routing_table[SUBNET_IN] = IFACE_IN
routing_table[SUBNET_OUT] = IFACE_OUT


def generate_port() -> int:
    port = randrange(200, 10000)
    while port in nat_table.keys():
        port = randrange(200, 10000)
    return port


def modify_packet(pkt):
    
    proto = TCP if TCP in pkt else (UDP if UDP in pkt else ICMP)
    
    # check if client is not connecting to the NAT
    # if not, then change the src ip to nat's ip
    if pkt.sniffed_on == IFACE_IN and pkt[IP].dst != NAT_IP:
        client_addr = (pkt[IP].src, pkt[proto].sport)

        if client_addr not in nat_table.values(): # new connection
            out_port = generate_port()
            nat_table[out_port] = client_addr
        else: # use existing connection
            out_port = [port for port, addr in nat_table.items() if addr == client_addr][0]
    
        pkt[IP].src = NAT_IP
        pkt[proto].sport = out_port

    # change the dst ip and port back to client's ip and port
    if pkt.sniffed_on == IFACE_OUT and pkt[IP].dst == NAT_IP:
        out_port = pkt[proto].dport

        pkt[IP].dst = nat_table[out_port][0]
        pkt[proto].dport = nat_table[out_port][1]

    return pkt


def route(pkt):    
    # modify packet before route
    pkt = modify_packet(pkt)
    
    for subnet in routing_table.keys():
        if ipaddress.ip_address(pkt[IP].dst) in ipaddress.ip_network(f"{subnet}.0/24"):
            # get only ingoing packets
            if pkt.sniffed_on != routing_table[subnet]:
                sendp(pkt, routing_table[subnet])


def main():
    sniff(iface=[IFACE_IN, IFACE_OUT], prn=route, filter="tcp or udp")


if __name__ == "__main__":
    main()
