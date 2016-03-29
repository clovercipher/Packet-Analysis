#!/usr/bin/env python
from scapy.all import *
from collections import defaultdict
import sys
'''
The dns-analysis.py library contains a number of functions which operate on a PCAP file
and analyze/process the data within that file. All information pertains to the DNS
protocol.
'''

'''
Variables
'''
pcap = sys.argv[1]
pkts = rdpcap(pcap)
dns_pkt_list = []
dns_dict = defaultdict(set)

'''
Process packets, retrieve DNS Request Records and places them into a list.
'''
for pkt in pkts:
    if pkt.haslayer('DNSRR'):
        dns_pkt_list.append(pkt)

'''
Builds dictionary of IP address to domain mapping;
Domain Name --> IP1, IP2, IP3...
dict{key:set([])}
returns: defaultdict(set)
'''
def build_dns_map():

    for pkt in dns_pkt_list:

        for i in range(0, len(pkt[DNSRR]) + 1):                                                             #Loop through second level of DNS Response Record packets

            try:
                if pkt[DNSRR][i].type == 1 or pkt[DNSRR][i].type == 28 or pkt[DNSRR][i].type == 15:           #DNS Type A (1) or AAAA(28) or MX(15)

                    dns_dict[pkt[DNSRR][i].rrname].add(pkt[DNSRR][i].rdata)                                #Add IP address to dictionary with key of domain name

            except IndexError:

                break

    return dns_dict.items()
'''
Print out the Domain and associated IP address mappings.
Function requires a dictionary.
'''
def print_dns(dns):
    dd = dns
    for k, v in dd:
        print k
        for ip in v:
            print '\t%s' %ip

dd = build_dns_map()
print_dns(dd)

