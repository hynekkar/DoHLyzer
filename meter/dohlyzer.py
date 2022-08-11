#!/usr/bin/env python

import argparse

from scapy.all import load_layer
from scapy.sendrecv import AsyncSniffer

from flow_session import generate_session_class

from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether
from scapy.layers.l2 import Dot1Q
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import IP

from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import *
from scapy.layers.http import *
from scapy.layers.dns import *
from scapy.layers.tls import *
from scapy.layers.ntp import *
from scapy.layers.rtp import *
from scapy.layers.smb import *
from scapy.layers.sctp import *
from scapy.layers.pptp import *
from scapy.layers.ppp import *
from scapy.layers.radius import *
from scapy.layers.tftp import *

import sys

class TrillPacket(Packet):
    name = "RTPDecPacket "
    fields_desc = [
        XBitField("version", 0, 2),
        XBitField("hlim", 0, 6),
        XBitField("mdest", 0, 1),
        XBitField("res", 0, 7),
        ShortField("inAddr", sys.maxsize),
        ShortField("eqAddr", sys.maxsize),
    ]


bind_layers(Dot1Q, TrillPacket, type=0x22f3)
bind_layers(TrillPacket, Ether)



def create_sniffer(input_file, input_interface, output_mode, output_file):
    assert (input_file is None) ^ (input_interface is None)

    NewFlowSession = generate_session_class(output_mode, output_file)

    if input_file is not None:
        return AsyncSniffer(offline=input_file, filter='tcp port 443', prn=None, session=NewFlowSession, store=False)
    else:
        return AsyncSniffer(iface=input_interface, filter='tcp port 443', prn=None,
                            session=NewFlowSession, store=False)


def main():
    parser = argparse.ArgumentParser()

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-n', '--online', '--interface', action='store', dest='input_interface',
                             help='capture online data from INPUT_INTERFACE')
    input_group.add_argument('-f', '--offline', '--file', action='store', dest='input_file',
                             help='capture offline data from INPUT_FILE')

    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument('-c', '--csv', '--flow', action='store_const', const='flow', dest='output_mode',
                              help='output flows as csv')
    output_group.add_argument('-s', '--json', '--sequence', action='store_const', const='sequence', dest='output_mode',
                              help='output flow segments as json')

    parser.add_argument('output', help='output file name (in flow mode) or directory (in sequence mode)')
    args = parser.parse_args()

    load_layer('tls')

    sniffer = create_sniffer(args.input_file, args.input_interface, args.output_mode, args.output)
    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()


if __name__ == '__main__':
    main()
