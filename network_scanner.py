#!/usr/bin/env python
import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range.")
    options, arguments = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # in Scapy, we can use '/' to append variables together. We are appending our broadcast MAC asking for our
    # destination IP addresses. We are setting a timeout because if you don't, your program will not finish as
    # it will continue to wait on machines that will not respond. we are typing verbose=false so scapy's srp
    # will display less information in the command prompt.
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []

    #Parsing the values captured in the answered list, using a loop to iterate over the list to return the
    #IP source and Hardware Source (MAC) from machines answering the ARP request we sent out
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("IP\t\t\tAt MAC Address\n-----------------------------------------")

    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)