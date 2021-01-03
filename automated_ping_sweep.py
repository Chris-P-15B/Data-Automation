#!/usr/bin/env python
# v1.3 - written by Chris Perkins in 2019
# Pulls interface IPv4 addresses & subnet masks via SNMP & pings each host IP in the connected network
# Requires that SNMP v2c is enabled & IP-MIB is supported on target device to work

# Portions of this code from get_routing_table.py v2.0, (c) Jarmo Pietiläinen 2013 - 2014, http://z0b.kapsi.fi/networking.php
# & used under the zlib/libpng licence.
# Python ping code courtesy of https://gist.github.com/pyos
# IP address sorting courtesy of https://www.python4networkengineers.com/posts/how_to_sort_ip_addresses_with_python/

# v1.3 - minor fixes
# v1.2 - added DNS reverse lookup
# v1.1 - code tidying
# v1.0 - initial release

# To Do:
# IPv6 support via 1.3.6.1.2.1.4.34 MIB
# Web GUI

import sys, ipaddress, time, random, struct, select, socket, threading, pysnmp
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

def extract_ip_from_oid(oid):
    """Given a dotted OID string, this extracts an IPv4 address from the end of it (i.e. the last four decimals)"""
    return ".".join(oid.split(".")[-4:])

def chk(data):
    """Python ping implementation"""
    x = sum(x << 8 if i % 2 else x for i, x in enumerate(data)) & 0xFFFFFFFF
    x = (x >> 16) + (x & 0xFFFF)
    x = (x >> 16) + (x & 0xFFFF)
    return struct.pack("<H", ~x & 0xFFFF)

def ping(addr, timeout=1, number=1, data=b""):
    """Python ping implementation"""
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

def ping_ip(ip_addr, ip_host_dict):
    """Ping an IP address after a small random delay to avoid rate limiting or saturation of ICMP traffic,
     also reverse DNS lookup on the IP address & store results in a dictionary"""
    time.sleep(random.random() * 1.2)
    if ping(ip_addr) is not None:
        try:
            reverse_dns = socket.gethostbyaddr(ip_addr)
        except socket.herror:
            ip_host_dict[ip_addr] = ""
        else:
            ip_host_dict[ip_addr] = reverse_dns[0]

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
        print(snmp_engine_error)
        sys.exit(1)

    if error_status:
        print(f"{error_status.prettyPrint()} at {error_index and variables[int(error_index) - 1][0] or '?'}")
        sys.exit(1)

    # Extract the data we need from the response
    if_index_to_name = {}
    if_index_to_address = {}
    if_ip_to_subnet_mask = {}
    longest = 0

    for r in variables:
        for name, val in r:
            oid = name.prettyPrint()
            value = val.prettyPrint()
            if (oid == "No more variables left in this MIB View" or
                    value == "No more variables left in this MIB View"):
                continue

            # 1-based index <-> interface name
            if oid[0:23] == "1.3.6.1.2.1.31.1.1.1.1.":
                if_index_to_name[int(oid[oid.rindex(".") + 1:])] = value
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
        print("Could not get the interface table, dumping raw data instead:")
        print(if_index_to_address)
        print(if_ip_to_subnet_mask)
        sys.exit(1)

    for i in if_index_to_name:
        padded_name = if_index_to_name[i].ljust(longest, ".") + ": "

        if i not in if_index_to_address:
            print(f"  {padded_name} (no address)")
            continue

        ip = if_index_to_address[i]

        if ip in if_ip_to_subnet_mask:
            mask = "/" + str(mask_to_prefix(if_ip_to_subnet_mask[ip]))
        else:
            mask = " (unknown subnet mask)"

        print(f"  {padded_name}{ip}{mask}")

        # Multi-threaded ping of valid host IP addresses for the network, ignoring loopback 127.0.0.0/8 addresses
        ip_and_host_dict = {}
        if ip[:int(ip.index("."))] != "127":
            workers = []
            for host_ip in list(ipaddress.IPv4Network(ip + mask, strict=False).hosts()):
                worker = threading.Thread(target=ping_ip, args=(host_ip.exploded, ip_and_host_dict))
                workers.append(worker)
                worker.start()
            for worker in workers:
                worker.join()

            # Display sorted list of IP addresses & hostnames that responded
            for ip_addr in sorted(ip_and_host_dict.keys(), key = lambda ip_addr: (int(ip_addr.split(".")[0]),
                int(ip_addr.split(".")[1]), int(ip_addr.split(".")[2]), int(ip_addr.split(".")[3]))):
                print(f"{ip_addr} {ip_and_host_dict[str(ip_addr)]}  UP")
    # Done
    sys.exit(0)