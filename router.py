from scapy.all import *
import ipaddress
from random import randrange
from firewall import *
from consts import *


# ROUTING TABLE
routing_table = {}  # subnet -> iface
routing_table[SUBNET_IN] = IFACE_IN
routing_table[SUBNET_OUT] = IFACE_OUT

# NAT TABLE
nat_table = {}  # router's out port -> (client's ip, client's in port)

# FIREWALL RULES
firewall = Firewall()
firewall.add_rule(False, dst_port=12345)


def generate_port() -> int:
    port = randrange(PORT_START_RANGE, PORT_END_RANGE)
    while port in nat_table.keys():
        port = randrange(PORT_START_RANGE, PORT_END_RANGE)
    return port


def handle_outgoing(pkt: packet, proto: Packet_metaclass) -> None:
    """
    check if client is not connecting to the NAT
    if not, then change the src ip to nat's ip
    """
    client_addr = (pkt[IP].src, pkt[proto].sport)

    if client_addr not in nat_table.values():  # new connection
        out_port = generate_port()
        nat_table[out_port] = client_addr
    else:  # use existing connection
        out_port = [port for port, addr in nat_table.items() if addr == client_addr][0]

    pkt[IP].src = NAT_IP
    pkt[proto].sport = out_port


def handle_ingoing(pkt: packet, proto: Packet_metaclass) -> None:
    """change the dst ip and port back to client's ip and port"""
    out_port = pkt[proto].dport

    pkt[IP].dst = nat_table[out_port][0]
    pkt[proto].dport = nat_table[out_port][1]


def modify_packet(pkt: packet):
    print("---------------before modify------------------")
    pkt.show()

    proto = TCP if TCP in pkt else UDP

    if pkt.sniffed_on == IFACE_IN and pkt[IP].dst != NAT_IP:
        handle_outgoing(pkt, proto)

    if pkt.sniffed_on == IFACE_OUT and pkt[IP].dst == NAT_IP:
        handle_ingoing(pkt, proto)

    print("---------------after modify------------------")
    pkt.show()
    return pkt


def route(pkt: packet) -> None:
    # filter packet thorugh firewall
    can_send_in = firewall.is_packet_permitted(pkt)

    # modify packet before route
    pkt = modify_packet(pkt)

    for subnet in routing_table.keys():
        if ipaddress.ip_address(pkt[IP].dst) in ipaddress.ip_network(subnet):
            # get only ingoing packets
            if pkt.sniffed_on != routing_table[subnet]:
                if not can_send_in:
                    print(
                        "-------------- Firewall dropped to following packet --------------"
                    )
                    pkt.show()

                else:
                    sendp(pkt, routing_table[subnet])

                break


def main():
    sniff(iface=[IFACE_IN, IFACE_OUT], prn=route, filter="ip and (tcp or udp)")


if __name__ == "__main__":
    main()
