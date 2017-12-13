import argparse
import sys
from datetime import datetime

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def print_spoof(tx_id, domain, res_1ist):

    print(datetime.now().strftime("%Y%m%d-%H:%M:%S.%f") + " DNS poisoning attempt")
    print("TXID {} Request {}".format(tx_id, domain))

    for count, ip_list in enumerate(res_1ist):
        print("Answer{} {}".format(count, ip_list[0]))

    print()


def get_rdata_list(res):

    ip_list = []
    for i in range(res.ancount):
        if res.an[i].type != 1:
            continue

        rdata = res.an[i].rdata

        if isinstance(rdata, str):
            ip_list.append(rdata)
        else:
            ip_list.append(rdata.decode("utf-8"))

    return ip_list


def pkt_parser(pkt):

    if pkt.haslayer(IP) and pkt.haslayer(DNS):
        if pkt[DNS].qr == 0:
            lookup_url = pkt[DNSQR].qname.decode("utf-8").rstrip('.')
            pkt_id = pkt[DNS].id

            if (lookup_url, pkt_id) not in detect_spoof:
                detect_spoof[(lookup_url, pkt_id)] = []
        else:
            lookup_url = pkt[DNSQR].qname.decode("utf-8").rstrip('.')
            pkt_id = pkt[DNS].id

            if (lookup_url, pkt_id) in detect_spoof:
                if len(detect_spoof[(lookup_url, pkt[DNS].id)]) == 0:
                    detect_spoof[(lookup_url, pkt[DNS].id)] = [(get_rdata_list(pkt[DNS]), pkt)]
                else:
                    dns_response_list = detect_spoof[(lookup_url, pkt_id)]
                    spoof = True

                    if pkt.haslayer(IPerror):
                        spoof = False
                    else:
                        for dns_rr in dns_response_list:
                            if pkt[IP].src == dns_rr[1][IP].src and pkt[IP].dst == dns_rr[1][IP].dst and \
                                ((pkt[UDP].sport == dns_rr[1][UDP].sport and pkt[UDP].dport == dns_rr[1][UDP].dport) or
                                 (pkt[TCP].sport == dns_rr[1][TCP].sport and pkt[TCP].dport == dns_rr[1][TCP].dport)) \
                               and sorted(get_rdata_list(pkt[DNS])) == sorted(dns_rr[0]):
                                spoof = False

                    if spoof:
                        dns_response_list.append((get_rdata_list(pkt[DNS]), pkt))
                        detect_spoof[(lookup_url, pkt_id)] = dns_response_list
                        print_spoof(pkt_id, lookup_url, dns_response_list)
            else:
                # We don't care about packet injection without DNS request.
                # This can be used for preventing DoS.
                pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("-i", type=str, dest="interface", help="Listening Interface on Network Device.")
    parser.add_argument("-r", type=str, dest="tracefile", help="Location of the Trace File.")
    parser.add_argument("expression", type=str, help="BPF Filter String.", default="", nargs="?")
    parser.add_argument('--help', action='store_true', default=False)

    args = parser.parse_args()

    if args.interface and args.tracefile:
        args.help = True

    if args.help:
        print("Usage: sudo python dnsdetect.py [-i interface] [-r tracefile] expression")
        print("-i: Listen on network device <interface> (e.g., eth0).")
        print("-r: Read packets from <tracefile> (tcpdump format).")
        print("expression: BPF filter that specifies a subset of the traffic to be monitored.")
        print("Use either -i or -r flag.")
        sys.exit(-1)

    expression = ""
    if args.expression:
        expression = args.expression

    detect_spoof = {}

    if args.interface:
        sniff(iface=args.interface, prn=pkt_parser, filter=expression, store=0)
    elif args.tracefile:
        sniff(offline=args.tracefile, prn=pkt_parser, filter=expression, store=0)
    else:
        sniff(iface=conf.iface, prn=pkt_parser, filter=expression, store=0)
