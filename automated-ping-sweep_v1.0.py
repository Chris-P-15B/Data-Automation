#!/usr/bin/env python
# v1.0 - written by Chris Perkins in 2019
# Pulls interface IPv4 addresses & subnet masks via SNMP & pings each host IP in the connected network
# Requires SNMP v2c enabled on target device to work

# Portions of this code from get_routing_table.py v2.0 (c) Jarmo Pietiläinen 2013 - 2014, http://z0b.kapsi.fi/snippets.php
# Python ping code courtesy of https://gist.github.com/pyos
# IP address sorting courtesy of https://www.python4networkengineers.com/posts/how_to_sort_ip_addresses_with_python/

# v1.0 – initial release

# To Do:
# IPv6 support via 1.3.6.1.2.1.4.34 MIB

import sys, ipaddress, time, random, struct, select, socket
from threading import Thread
from pysnmp.entity.rfc3413.oneliner import cmdgen

# Subnet mask -> CIDR prefix length lookup table
subnet_masks = {
    "128.0.0.0" : 1, "255.128.0.0" : 9,  "255.255.128.0" : 17, "255.255.255.128" : 25,
    "192.0.0.0" : 2, "255.192.0.0" : 10, "255.255.192.0" : 18, "255.255.255.192" : 26,
    "224.0.0.0" : 3, "255.224.0.0" : 11, "255.255.224.0" : 19, "255.255.255.224" : 27,
    "240.0.0.0" : 4, "255.240.0.0" : 12, "255.255.240.0" : 20, "255.255.255.240" : 28,
    "248.0.0.0" : 5, "255.248.0.0" : 13, "255.255.248.0" : 21, "255.255.255.248" : 29,
    "252.0.0.0" : 6, "255.252.0.0" : 14, "255.255.252.0" : 22, "255.255.255.252" : 30,
    "254.0.0.0" : 7, "255.254.0.0" : 15, "255.255.254.0" : 23, "255.255.255.254" : 31,
    "255.0.0.0" : 8, "255.255.0.0" : 16, "255.255.255.0" : 24, "255.255.255.255" : 32
}

def mask_to_prefix(mask):
    """Subnet mask -> prefix length, returns 0 if invalid/zero"""
    return subnet_masks.get(mask, 0)

def is_valid_ip(ip_str):
    """Returns True if the IP address is valid, False if not"""
    try:
        b = [int(o) for o in ip_str.strip().split('.')]
    except:
        return False

    if (len(b) != 4) or (min(b) < 0) or (max(b) > 255):
        return False

    return True

def extract_ip_from_oid(oid):
    """Given a dotted OID string, this extracts an IPv4 address from # the end of it (i.e. the last four decimals)"""
    return '.'.join(oid.split('.')[-4:])

def chk(data):
    """ Ping code from https://gist.github.com/pyos"""
    x = sum(x << 8 if i % 2 else x for i, x in enumerate(data)) & 0xFFFFFFFF
    x = (x >> 16) + (x & 0xFFFF)
    x = (x >> 16) + (x & 0xFFFF)
    return struct.pack("<H", ~x & 0xFFFF)

def ping(addr, timeout=1, number=1, data=b''):
    """ Ping code from https://gist.github.com/pyos"""
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as conn:
        payload = struct.pack("!HH", random.randrange(0, 65536), number) + data

        conn.connect((addr, 80))
        conn.sendall(b"\x08\0" + chk(b"\x08\0\0\0" + payload) + payload)
        start = time.time()

        while select.select([conn], [], [], max(0, start + timeout - time.time()))[0]:
            data = conn.recv(65536)
            if len(data) < 20 or len(data) < struct.unpack_from("!xxH", data)[0]:
                continue
            if data[20:] == b"\0\0" + chk(b"\0\0\0\0" + payload) + payload:
                return time.time() - start

def ping_ip(ip_addr, results_list):
    """Ping an IP address after a small random delay to avoid rate limiting or saturation of ICMP traffic"""
    time.sleep(random.random() * 1.2)
    if ping(ip_addr) != None:
        results_list.append(ip_addr)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        quit("Usage: automated-ping-sweep.py <target IP> <community string>")

    ip = sys.argv[1]
    if not is_valid_ip(sys.argv[1]):
        quit("%s is not a valid IPv4 address" % (ip))

    command_generator = cmdgen.CommandGenerator()
    authentication = cmdgen.CommunityData(sys.argv[2])
    target = cmdgen.UdpTransportTarget((ip, 161))

    # Send a GETBULK request for the OIDs we want
    snmp_engine_error, error_status, error_index, variables = command_generator.bulkCmd(
        authentication, target, 0, 25,
        # Interface index <-> IP address
        "1.3.6.1.2.1.4.20.1.2",
        # Interface IP <-> subnet mask
        "1.3.6.1.2.1.4.20.1.3",
        # Interface index <-> name (MIB extensions)
        "1.3.6.1.2.1.31.1.1.1.1",
        lookupMib=False, lexicographicMode=False
    )

    if snmp_engine_error:
        quit(snmp_engine_error)

    if error_status:
        quit("%s at %s" % (error_status.prettyPrint(), error_index and variables[int(error_index) - 1][0] or '?'))

    # Extract the data we need from the response
    if_index_to_name = {}
    if_index_to_address = {}
    if_ip_to_subnet_mask = {}
    longest = 0

    for r in variables:
        for name, val in r:
            oid = name.prettyPrint()
            value = val.prettyPrint()

            if oid == "No more variables left in this MIB View" or value == "No more variables left in this MIB View":
                continue

            # 1-based index <-> interface name
            if oid[0:23] == "1.3.6.1.2.1.31.1.1.1.1.":
                if_index_to_name[int(oid[oid.rindex('.') + 1:])] = value
                longest = max(longest, len(value))
            # 1-based index <-> interface ip address
            if oid[0:20] == "1.3.6.1.2.1.4.20.1.2":
                if_index_to_address[int(value)] = extract_ip_from_oid(oid)
            # IP address <-> subnet mask
            if oid[0:20] == "1.3.6.1.2.1.4.20.1.3":
                if_ip_to_subnet_mask[extract_ip_from_oid(oid)] = value

    # Print a list of interfaces
    print("Interfaces")

    if len(if_index_to_name) == 0:
        print("Could not get the interface table, dumping raw data instead")
        print(if_index_to_address)
        print(if_ip_to_subnet_mask)
        sys.exit()

    for i in if_index_to_name:
        padded_name = if_index_to_name[i].ljust(longest, '.') + ": "

        if i not in if_index_to_address:
            print("  " + padded_name + " (no address)")
            continue

        ip = if_index_to_address[i]

        if ip in if_ip_to_subnet_mask:
            mask = '/' + str(mask_to_prefix(if_ip_to_subnet_mask[ip]))
        else: mask = " (unknown subnet mask)"

        print("  " + padded_name + ip + mask)

        # Multi-threaded ping of valid host IP addresses for the network, ignoring loopback 127.0.0.0/8 addresses
        # adding results to a list of IP addresses that responded
        result_list = []
        threads = []
        if ip[:int(ip.index('.'))] != "127":
            for host_ip in list(ipaddress.IPv4Network(ip + mask, strict=False).hosts()):
                worker = Thread(target=ping_ip, args=(host_ip.exploded, result_list))
                worker.start()
                threads.append(worker)
            for worker in threads:
                worker.join()
        # Display sorted list of IP addresses that responded
        for ip_addr in sorted(result_list, key = lambda ip_addr: (
                int(ip_addr.split('.')[0]), int(ip_addr.split('.')[1]),
                int(ip_addr.split('.')[2]), int(ip_addr.split('.')[3]))):
            print(ip_addr + " up")