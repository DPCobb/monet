import click
import os
import platform
import scapy.all as scapy
from terminaltables import AsciiTable
import requests
import json


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
    output = []
    while i < int(request):
        req = scapy.ARP()
        req.pdst = str(target)
        ether = scapy.Ether()
        ether.dst = 'ff:ff:ff:ff:ff:ff'
        packet = ether / req
        result = scapy.srp(packet, timeout=5, verbose=False)[0]
        output = [["IP Address", "MAC Address", "Vendor"]]
        for r in result:
            ipR = r[1].psrc
            if ipR not in discovered:
                MAC_URL = 'http://macvendors.co/api/%s'
                mac_r = requests.get(MAC_URL % str(r[1].hwsrc))
                mac_rP = mac_r.json()
                d = [r[1].psrc, r[1].hwsrc, mac_rP['result']['company']]
                output.append(d)
                discovered.append(r[1].psrc)
        i += 1

    table = AsciiTable(output)
    print(table.table)


@network.command()
@click.option('--target', '--t', required=True, type=str, help="IP range to scan, ex: 192.168.1.1-254")
def icmp_ping(target):
    """ICMP Ping Scan, a basic port scan using ICMP echo requests, replies indicate the source is alive."""
    ans, unans = scapy.sr(scapy.IP(dst=str(target))/scapy.ICMP(), timeout=5)
    output = [["IP Address"]]
    for r in ans:
        d = [r[1].src]
        output.append(d)
    table = AsciiTable(output)
    print(table.table)
