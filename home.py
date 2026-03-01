from scapy.all import *

IFACE = r"\Device\NPF_{BBFAF8BF-8879-4C10-83D4-705B892AA256}"
ENP0S8_MAC = "08:00:27:61:cb:8f"

def main():
    pkt = Ether(dst=ENP0S8_MAC)/IP(dst="www.example.com")/TCP(dport=80, flags="S")
    pkt.show()
    sendp(pkt, iface=IFACE)
    sniff(iface=IFACE)


if __name__ == "__main__":
    main()
