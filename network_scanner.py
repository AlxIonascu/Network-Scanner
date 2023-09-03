#!/usr/bin/env python

import scapy.all as scapy
import optparse

'''Gets arguments specifying the target to be scanned'''


def get_argument():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="IP or IP range target to scan")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target, use --help for more info.")
    return options


'''Performs the scan of the specified IP or IP range'''


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)  # set the arp request to the parameter ip
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # create an ethernet object
    arp_req_broadcast = broadcast / arp_request  # combining both packets into one
    answered_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[
        0]  # sends the packet and returns the answered lists
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


'''Displays the result of the scan'''


def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for element in results_list:
        print(element["ip"] + "\t\t" + element["mac"])


option = get_argument()
scan_result = scan(option.target)
print_result(scan_result)
