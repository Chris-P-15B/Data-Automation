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

The S in SNMP standing for "Simple" is a lie!

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

import pkgutil
import time
import random
import socket
import sys
import ipaddress
import threading
import pysnmp
from ping import Ping
from pysnmp.entity.rfc3413.oneliner import cmdgen


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


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <target IP> <community string>")
        sys.exit(1)

    ip = sys.argv[1]
    command_generator = cmdgen.CommandGenerator()
    authentication = cmdgen.CommunityData(sys.argv[2])
    try:
        target = cmdgen.UdpTransportTarget((ip, 161))
    except pysnmp.error.PySnmpError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Send a GETBULK request for the OIDs we want
    snmp_engine_error, error_status, error_index, variables = command_generator.bulkCmd(
        authentication,
        target,
        0,
        25,
        # Interface index <-> name (MIB extensions)
        "1.3.6.1.2.1.31.1.1.1.1",
        lookupMib=False,
        lexicographicMode=False,
    )

    if snmp_engine_error:
        print(snmp_engine_error)
        sys.exit(1)

    if error_status:
        print(
            f"{error_status.prettyPrint()} at {error_index and variables[int(error_index) - 1][0] or '?'}"
        )
        sys.exit(1)

    # Extract the interface indexes & names we need from the response
    if_index_to_name = {}
    if_index_to_ipv4_address = {}
    if_index_to_ipv6_address = {}
    longest = 0

    for r in variables:
        for name, val in r:
            oid = name if isinstance(name, str) else name.prettyPrint()
            value = val.prettyPrint()
            if (
                oid == "No more variables left in this MIB View"
                or value == "No more variables left in this MIB View"
            ):
                continue

            # 1-based index <-> interface name
            if oid[0:23] == "1.3.6.1.2.1.31.1.1.1.1.":
                if_index = oid[oid.rindex(".") + 1 :]
                if_index_to_name[if_index] = value
                longest = max(longest, len(value))

                if if_index_to_ipv4_address.get(if_index, True):
                    if_index_to_ipv4_address[if_index] = []
                if if_index_to_ipv6_address.get(if_index, True):
                    if_index_to_ipv6_address[if_index] = []

    # Send a GETBULK request for the OIDs we want
    snmp_engine_error, error_status, error_index, variables = command_generator.bulkCmd(
        authentication,
        target,
        0,
        25,
        # Interface index <-> IP address
        "1.3.6.1.2.1.4.34",
        # Interface IP <-> subnet mask
        "1.3.6.1.2.1.4.32",
        lookupMib=False,
        lexicographicMode=False,
    )

    if snmp_engine_error:
        print(snmp_engine_error)
        sys.exit(1)

    if error_status:
        print(
            f"{error_status.prettyPrint()} at {error_index and variables[int(error_index) - 1][0] or '?'}"
        )
        sys.exit(1)

    # Extract the IP addressing from the response
    if_unicast_addresses = []

    for r in variables:
        for name, val in r:
            oid = name if isinstance(name, str) else name.prettyPrint()
            value = val.prettyPrint()
            if (
                oid == "No more variables left in this MIB View"
                or value == "No more variables left in this MIB View"
            ):
                continue

            # Confirm unicast IP addresses
            if oid[0:20] == "1.3.6.1.2.1.4.34.1.4" and value == "1":
                if oid[21] in ("1", "3"):
                    if_unicast_addresses.append(extract_ip_from_oid(oid, True))
                if oid[21] in ("2", "4"):
                    if_unicast_addresses.append(extract_ip_from_oid(oid, False))

            # 1-based index <-> interface IP address
            if (
                oid[0:20] == "1.3.6.1.2.1.4.34.1.5"
                and value[0:16] == "1.3.6.1.2.1.4.32"
            ):
                ip_addr = ""
                # IPv4
                if oid[21] in ("1", "3"):
                    if extract_ip_from_oid(oid, True) in if_unicast_addresses:
                        ip_addr = f"{extract_ip_from_oid(oid, True)}/{extract_mask_from_value(value)}"
                        if_index_to_ipv4_address[value.split(".")[10]].append(ip_addr)
                # IPv6
                if oid[21] in ("2", "4"):
                    if extract_ip_from_oid(oid, False) in if_unicast_addresses:
                        ip_addr = f"{extract_ip_from_oid(oid, False)}/{extract_mask_from_value(value)}"
                        if_index_to_ipv6_address[value.split(".")[10]].append(ip_addr)

    # Print a list of interfaces
    print("Interfaces")

    if len(if_index_to_name) == 0:
        print("Could not get the interface table, dumping raw data instead:")
        print(if_index_to_name)
        print(if_index_to_ipv4_address)
        print(if_index_to_ipv6_address)
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
    sys.exit(0)
