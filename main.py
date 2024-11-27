import optparse
import scapy.all as sp

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface name to check packets")
    (options, arguments) = parser.parse_args()

    if not options.interface:
        parser.error("Please input Interface name, use --help for more info.")
    return options

def get_mac(ip):
    arp_request = sp.ARP(pdst=ip)
    broadcast = sp.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = sp.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    return answered_list[0][1].hwsrc

def sniff(interface):
    sp.sniff(iface=interface, store=False,prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    try:
        if packet.haslayer(sp.ARP) and packet[sp.ARP].op == 2:
            real_mac = get_mac(packet[sp.ARP].psrc)
            response_mac = packet[sp.ARP].hwsrc

            if real_mac != response_mac:
                print("[+] You are under attack!!")

    except IndexError:
        pass

interface_name = get_arguments()
sniff(interface_name.interface)
