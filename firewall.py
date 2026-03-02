from scapy.all import *
from dataclasses import dataclass


@dataclass
class FirewallRule:
    is_tcp: bool
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str


class Firewall:
    def __init__(self):
        self.firewall_rules: list[FirewallRule] = []

    def add_rule(
        self,
        is_tcp: bool,
        src_mac: str = None,
        dst_mac: str = None,
        src_ip: str = None,
        dst_ip: str = None,
        src_port: str = None,
        dst_port: str = None,
    ) -> None:
        self.firewall_rules.append(
            FirewallRule(is_tcp, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port)
        )

    def is_packet_permitted(self, pkt: packet) -> bool:
        """return True if the packet is permitted, else False"""
        proto = TCP if TCP in pkt else UDP

        is_permitted = True
        for rule in self.firewall_rules:
            is_permitted = proto == TCP if rule.is_tcp else proto == UDP
            is_permitted &= (
                pkt[Ether].src != rule.src_mac if rule.src_mac != None else True
            )
            is_permitted &= (
                pkt[Ether].dst != rule.dst_mac if rule.dst_mac != None else True
            )
            is_permitted &= pkt[IP].src != rule.src_ip if rule.src_ip != None else True
            is_permitted &= pkt[IP].dst != rule.dst_ip if rule.dst_ip != None else True
            is_permitted &= (
                pkt[proto].sport != rule.src_port if rule.src_port != None else True
            )
            is_permitted &= (
                pkt[proto].dport != rule.dst_port if rule.dst_port != None else True
            )

        return is_permitted
