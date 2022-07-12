#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


from scapy.all import srp, ARP, Ether, sniff
from argparse import ArgumentParser


class pywall:
    def __init__(self, iface=None, timeout=15):
        self.iface = iface
        self.timeout = timeout
        self.arp_spoofing_detected = None

    def get_mac_address(self, target):
        """
        Get mac address of target
        """
        result = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target), timeout=3, verbose=0
        )[0]
        result = [received.hwsrc for sent, received in result]

    def arp_spoofing_detection(self):
        """
        Detect arp spoofing
        """

        def __control(packet):
            return self.arp_spoofing_detected is not None

        def __process_sniffed_packet(packet):
            if packet.haslayer(ARP) and packet[ARP].op == 2:
                real_mac = self.get_mac_address(packet[ARP].psrc)
                response_mac = packet[ARP].hwsrc
                self.arp_spoofing_detected = real_mac != response_mac

        sniff(
            iface=self.iface,
            store=False,
            stop_filter=__control,
            prn=__process_sniffed_packet,
            timeout=self.timeout,
        )

        return self.arp_spoofing_detected

    def control(self):
        """
        Main function
        """

        return self.arp_spoofing_detection()


def arguments():
    """
    Main function
    """

    parser = ArgumentParser()
    parser.add_argument("-i", "--iface", type=str, help="Interface")
    parser.add_argument("-t", "--timeout", type=int, help="Timeout")

    args = parser.parse_args()

    the_pywall = pywall()

    if args.iface is not None:
        the_pywall.iface = args.iface
    if args.timeout is not None:
        the_pywall.timeout = args.timeout

    print(the_pywall.control())


if __name__ == "__main__":
    print(pywall().control())
