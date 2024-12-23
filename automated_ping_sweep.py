#!/usr/bin/env python3

"""
Copyright (c) 2019 - 2024, Chris Perkins
Licence: BSD 3-Clause

Pulls interface IP addresses & subnet masks via SNMP, then pings each host IP in the connected network.
Requires that SNMP v2c is enabled & IP-MIB is supported on target device to work.

Portions of this code from get_routing_table.py v2.0, (c) Jarmo Pietiläinen 2013 - 2014, http://z0b.kapsi.fi/networking.php
& used under the zlib/libpng licence.
Python ping code courtesy of https://gist.github.com/zador-blood-stained
IP address sorting courtesy of https://www.python4networkengineers.com/posts/how_to_sort_ip_addresses_with_python/
Thanks to http://www.net-snmp.org/docs/mibs/ip.html for explaining the OIDs

The S in SNMP standing for "Simple" is a lie!

v1.6.1 - Reworked to use PySNNP v7.1+.
v1.6 - Using "1.3.6.1.2.1.4.32" & "1.3.6.1.2.1.4.34" OIDs to support more vendors, IPv6 & interfaces with multiple IP addresses.
v1.5 - Bug fix.
v1.4 - Fixed handling /31 networks.
v1.3 - Minor fixes.
v1.2 - Added DNS reverse lookup.
v1.1 - Code tidying.
v1.0 - Initial release.

To Do:

Web GUI
"""

import time
import random
import socket
import sys
import ipaddress
import threading
from ping import Ping
import asyncio
from pysnmp.hlapi.v1arch.asyncio import *


def extract_ip_from_oid(oid, ipv4=True):
    """Given a dotted OID string, this extracts an IP address from the end of it"""
    # IPv4 = the last four decimals, convert to dottted decimal notation
    if ipv4:
        return ".".join(oid.split(".")[-4:])
    # IPv6 = the last 16 decimals & need to convert to correct hex notation
    else:
        hex = "".join([f"{int(i):02x}" for i in oid.split(".")[-16:]])
        return f"{hex[0:4]}:{hex[4:8]}:{hex[8:12]}:{hex[12:16]}:{hex[16:20]}:{hex[20:24]}:{hex[24:28]}:{hex[28:32]}"


def extract_mask_from_value(value):
    """Given a dotted value string, this extracts a subnet mask from the end of it"""
    return value.split(".")[-1:][0]


def ping_ip(ip_addr, ip_host_dict):
    """Ping an IP address after a small random delay to avoid rate limiting or saturation of ICMP traffic,
    also reverse DNS lookup on the IP address & store results in a dictionary"""
    time.sleep(random.random() * 1.2)
    p = Ping()
    if "." in ip_addr:
        if p.ping(ip_addr) is not None:
            try:
                reverse_dns = socket.gethostbyaddr(ip_addr)
            except socket.herror:
                ip_host_dict[ip_addr] = ""
            else:
                ip_host_dict[ip_addr] = reverse_dns[0]
    elif ":" in ip_addr:
        if p.ping6(ip_addr) is not None:
            try:
                reverse_dns = socket.gethostbyaddr(ip_addr)
            except socket.herror:
                ip_host_dict[ip_addr] = ""
            else:
                ip_host_dict[ip_addr] = reverse_dns[0]
    p.close()


async def run():
    """SNMP poll of the device's interfaces & their IP addresses"""
    snmpDispatcher = SnmpDispatcher()
    if_index_to_name = {}
    if_index_to_ipv4_address = {}
    if_index_to_ipv6_address = {}
    longest = 0
    if_unicast_addresses = []

    searching = True
    # Interface index <-> name (MIB extensions)
    var_binds = [ObjectType(ObjectIdentity("1.3.6.1.2.1.31.1.1.1.1"))]
    while searching:
        error_indication, error_status, error_index, var_bind_table = await bulk_cmd(
            snmpDispatcher,
            CommunityData(sys.argv[2], mpModel=1),
            await UdpTransportTarget.create((sys.argv[1], 161)),
            0,
            50,
            *var_binds,
        )

        if error_indication:
            print(error_indication)
            snmpDispatcher.transport_dispatcher.close_dispatcher()
            sys.exit(1)

        elif error_status:
            print(error_status.prettyPrint())
            print(
                "{} at {}".format(
                    error_status.prettyPrint(),
                    error_index and var_bind_table[int(error_index) - 1][0] or "?",
                )
            )
            snmpDispatcher.transport_dispatcher.close_dispatcher()
            sys.exit(1)

        else:
            # Extract the interface indexes & names we need from the response
            for var_bind in var_bind_table:
                pretty_printed = "=".join([x.prettyPrint() for x in var_bind])
                oid = pretty_printed.split("=")[0]
                value = pretty_printed.split("=")[1]
                # 1-based index <-> interface name
                if oid[17:29] == ".31.1.1.1.1.":
                    if_index = oid[oid.rindex(".") + 1 :]
                    if_index_to_name[if_index] = value
                    longest = max(longest, len(value))

                    if if_index_to_ipv4_address.get(if_index, True):
                        if_index_to_ipv4_address[if_index] = []
                    if if_index_to_ipv6_address.get(if_index, True):
                        if_index_to_ipv6_address[if_index] = []
                else:
                    searching = False
                    break

        var_binds = var_bind_table
        if is_end_of_mib(var_binds):
            break

    searching = True
    # Interface index <-> IP address & Interface IP <-> subnet mask
    var_binds = [ObjectType(ObjectIdentity("1.3.6.1.2.1.4.34.1.4"))]
    while searching:
        error_indication, error_status, error_index, var_bind_table = await bulk_cmd(
            snmpDispatcher,
            CommunityData(sys.argv[2], mpModel=1),
            await UdpTransportTarget.create((sys.argv[1], 161)),
            0,
            50,
            *var_binds,
        )

        if error_indication:
            print(error_indication)
            snmpDispatcher.transport_dispatcher.close_dispatcher()
            sys.exit(1)

        elif error_status:
            print(
                "{} at {}".format(
                    error_status.prettyPrint(),
                    error_index and var_bind_table[int(error_index) - 1][0] or "?",
                )
            )
            snmpDispatcher.transport_dispatcher.close_dispatcher()
            sys.exit(1)

        else:
            # Extract the IP addressing from the response
            for var_bind in var_bind_table:
                pretty_printed = "=".join([x.prettyPrint() for x in var_bind])
                oid = pretty_printed.split("=")[0]
                value = pretty_printed.split("=")[1]
                # Confirm unicast IP addresses
                if oid[17:27] == ".4.34.1.4." and value == "1":
                    if oid[27:29] in ("1.", "3."):
                        if_unicast_addresses.append(extract_ip_from_oid(oid, True))
                    if oid[27:29] in ("2.", "4."):
                        if_unicast_addresses.append(extract_ip_from_oid(oid, False))
                else:
                    searching = False
                    break

        var_binds = var_bind_table
        if is_end_of_mib(var_binds):
            break

    searching = True
    # Interface index <-> IP address & Interface IP <-> subnet mask
    var_binds = [ObjectType(ObjectIdentity("1.3.6.1.2.1.4.34.1.5"))]
    while searching:
        error_indication, error_status, error_index, var_bind_table = await bulk_cmd(
            snmpDispatcher,
            CommunityData(sys.argv[2], mpModel=1),
            await UdpTransportTarget.create((sys.argv[1], 161)),
            0,
            50,
            *var_binds,
        )

        if error_indication:
            print(error_indication)
            snmpDispatcher.transport_dispatcher.close_dispatcher()
            sys.exit(1)

        elif error_status:
            print(
                "{} at {}".format(
                    error_status.prettyPrint(),
                    error_index and var_bind_table[int(error_index) - 1][0] or "?",
                )
            )
            snmpDispatcher.transport_dispatcher.close_dispatcher()
            sys.exit(1)

        else:
            # Extract the IP addressing from the response
            for var_bind in var_bind_table:
                pretty_printed = "=".join([x.prettyPrint() for x in var_bind])
                oid = pretty_printed.split("=")[0]
                value = pretty_printed.split("=")[1]
                # 1-based index <-> interface IP address
                if oid[17:27] == ".4.34.1.5." and value[0:16] == "1.3.6.1.2.1.4.32":
                    ip_addr = ""
                    # IPv4
                    if oid[27:29] in ("1.", "3."):
                        if extract_ip_from_oid(oid, True) in if_unicast_addresses:
                            ip_addr = f"{extract_ip_from_oid(oid, True)}/{extract_mask_from_value(value)}"
                            if_index_to_ipv4_address[value.split(".")[10]].append(
                                ip_addr
                            )
                    # IPv6
                    if oid[27:29] in ("2.", "4."):
                        if extract_ip_from_oid(oid, False) in if_unicast_addresses:
                            ip_addr = f"{extract_ip_from_oid(oid, False)}/{extract_mask_from_value(value)}"
                            if_index_to_ipv6_address[value.split(".")[10]].append(
                                ip_addr
                            )
                else:
                    searching = False
                    break

        var_binds = var_bind_table
        if is_end_of_mib(var_binds):
            break

    # Print a list of interfaces
    print("Interfaces")

    if len(if_index_to_name) == 0:
        print("Could not get the interface table, dumping raw data instead:")
        print(if_index_to_name)
        print(if_index_to_ipv4_address)
        print(if_index_to_ipv6_address)
        snmpDispatcher.transport_dispatcher.close_dispatcher()
        sys.exit(1)

    for i in if_index_to_name:
        padded_name = if_index_to_name[i].ljust(longest, ".") + ": "

        # Multi-threaded ping of valid host IPv4 addresses for the network, ignoring loopback 127.0.0.0/8 addresses
        ip_addresses = if_index_to_ipv4_address.get(i, [])
        if ip_addresses:
            for ip in ip_addresses:
                print(f"  {padded_name}{ip}")

                ip_and_host_dict = {}
                if ip[:3] != "127":
                    workers = []
                    # Determine list of IPv4 addresses
                    ip_network = ipaddress.IPv4Network(ip, strict=False)
                    for host_ip in ip_network.hosts():
                        worker = threading.Thread(
                            target=ping_ip, args=(host_ip.exploded, ip_and_host_dict)
                        )
                        workers.append(worker)
                        worker.start()
                    for worker in workers:
                        worker.join()

                    # Display sorted list of IPv4 addresses & hostnames that responded
                    for ip_addr in sorted(
                        ip_and_host_dict.keys(),
                        key=lambda ip_addr: (
                            int(ip_addr.split(".")[0]),
                            int(ip_addr.split(".")[1]),
                            int(ip_addr.split(".")[2]),
                            int(ip_addr.split(".")[3]),
                        ),
                    ):
                        print(f"{ip_addr} {ip_and_host_dict[str(ip_addr)]}  UP")
        else:
            print(f"  {padded_name} (IPv4 no address)")

        # Multi-threaded ping of valid host IPv6 addresses for the network, ignoring loopback ::1/128
        # and fe80::/10 link local addresses
        ip_addresses = if_index_to_ipv6_address.get(i, [])
        if ip_addresses:
            for ip in ip_addresses:
                print(f"  {padded_name}{ip}")

                ip_and_host_dict = {}
                if ip[:39] != "0000:0000:0000:0000:0000:0000:0000:0001" and ip[
                    :3
                ] not in (
                    "fe8",
                    "fe9",
                    "fea",
                    "feb",
                ):
                    workers = []
                    # Determine list of IPv6 addresses
                    ip_network = ipaddress.IPv6Network(ip, strict=False)
                    for host_ip in ip_network.hosts():
                        worker = threading.Thread(
                            target=ping_ip, args=(host_ip.exploded, ip_and_host_dict)
                        )
                        workers.append(worker)
                        worker.start()
                    for worker in workers:
                        worker.join()

                    # Display sorted list of IPv6 addresses & hostnames that responded
                    for ip_addr in sorted(
                        ip_and_host_dict.keys(),
                        key=lambda ip_addr: (
                            int(ip_addr.split(":")[0], 16),
                            int(ip_addr.split(":")[1], 16),
                            int(ip_addr.split(":")[2], 16),
                            int(ip_addr.split(":")[3], 16),
                            int(ip_addr.split(":")[4], 16),
                            int(ip_addr.split(":")[5], 16),
                            int(ip_addr.split(":")[6], 16),
                            int(ip_addr.split(":")[7], 16),
                        ),
                    ):
                        print(f"{ip_addr} {ip_and_host_dict[str(ip_addr)]}  UP")
        else:
            print(f"  {padded_name} (IPv6 no address)")

    # Done
    snmpDispatcher.transport_dispatcher.close_dispatcher()
    sys.exit(0)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <target IP> <community string>")
        sys.exit(1)

    asyncio.run(run())


if __name__ == "__main__":
    main()
