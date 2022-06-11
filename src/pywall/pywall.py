import scapy.all as ARP, srp, Ether, sniffer


def get_mac_address(target):
        """
        Get mac address of target
        """
        result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=3, verbose=0)[0]
        result  = [received.hwsrc for sent, received in result]


def arp_spoofing_detection(iface):
        """
        Detect arp spoofing
        """

        global arp_spoofing_detected
        arp_spoofing_detected = None

        def control(packet):
            global arp_spoofing_detected
            if arp_spoofing_detected is not None:
                return True
            else:
                return False


        def process_sniffed_packet(packet):
            global arp_spoofing_detected
            if packet.haslayer(ARP) and packet[ARP].op == 2:
                real_mac = get_mac_address(packet[ARP].psrc)
                response_mac = packet[ARP].hwsrc
                if real_mac != response_mac:
                    arp_spoofing_detected = True
                else:
                    arp_spoofing_detected = False

        sniffer(iface=iface, store=False, stop_filter=control,  prn=process_sniffed_packet)