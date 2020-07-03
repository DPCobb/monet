import click
import os
import platform
import scapy.all as scapy
from terminaltables import AsciiTable
import requests
import json
from colorclass import Color, Windows
import socket


@click.group()
def network():
    pass


@network.command()
@click.option('--target', '--t', required=True, type=str, help="IP range to scan, ex: 192.168.1.1/24")
@click.option('--request', '--r', type=int, default=3, help="How many times should we repeat this scan to collect results")
def scan_network(target, request):
    """Basic network scan using an ARP Request"""
    discovered = []
    i = 0
    output = [["IP Address", "MAC Address", "Vendor", "Name"]]
    while i < int(request):
        req = scapy.ARP()
        req.pdst = str(target)
        ether = scapy.Ether()
        ether.dst = 'ff:ff:ff:ff:ff:ff'
        packet = ether / req
        result = scapy.srp(packet, timeout=5, verbose=False)[0]
        for r in result:
            ipR = r[1].psrc
            if ipR not in discovered:
                MAC_URL = 'http://macvendors.co/api/%s'
                mac_r = requests.get(MAC_URL % str(r[1].hwsrc))
                mac_rP = mac_r.json()
                try:
                    hostname = socket.gethostbyaddr(ipR)[0]
                except:
                    hostname = ""
                d = [r[1].psrc, r[1].hwsrc, mac_rP['result']
                     ['company'], hostname]
                output.append(d)
                discovered.append(r[1].psrc)
        i += 1

    table = AsciiTable(output)
    print(table.table)


@network.command()
@click.option('--target', '--t', required=True, type=str, help="IP range to scan, ex: 192.168.1.1-254")
def icmp_ping(target):
    """ICMP Ping Scan, a basic port scan using ICMP echo requests, replies indicate the source is alive."""
    ans, unans = scapy.sr(scapy.IP(dst=str(target))/scapy.ICMP(), timeout=10)
    output = [["IP Address"]]
    for r in ans:
        d = [r[1].src]
        output.append(d)
    table = AsciiTable(output)
    print(table.table)


@network.command()
@click.option('--target', '--t', required=True, type=str, help="IP to scan, ex: 192.168.1.1")
@click.option('--openonly', '--o', is_flag=True, default=False, help="Only display open ports")
def tcp_scan(target, openonly):
    """Simple TCP Port Scan"""
    print("Running TCP Port Scan... \n")
    res, unans = scapy.sr(scapy.IP(dst=str(target)) /
                          scapy.TCP(flags="S", dport=(1, 1024)), timeout=5, verbose=False)
    output = [["Source IP", "Source Port",
               "Status"]]
    for r in res:
        if r[1]['TCP'].flags == 0x12:
            d = [r[1].src, r[1]['TCP'].sport, Color(
                '{autogreen}Open{/autogreen}')]
            output.append(d)
        else:
            if openonly == False:
                d = [r[1].src, r[1]['TCP'].sport, Color(
                    '{autored}Closed{/autored}')]
                output.append(d)
    table = AsciiTable(output)
    print(table.table)
