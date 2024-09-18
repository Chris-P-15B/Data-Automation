#!/usr/bin/env python3

"""
Python ping code courtesy of https://gist.github.com/zador-blood-stained
"""

import time
import random
import select
import socket
import struct
import os
import sys

ICMP_ECHOREPLY = 0  # Echo reply (per RFC792)
ICMP_ECHO = 8  # Echo request (per RFC792)
ICMP_ECHO_IPV6 = 128  # Echo request (per RFC4443)
ICMP_ECHO_IPV6_REPLY = 129  # Echo request (per RFC4443)


class Ping:
    def __init__(self):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.conn6 = socket.socket(
            socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6
        )
        self.own_id = os.getpid() & 0xFFFF

    def chk(self, data):
        x = (
            sum(a + b * 256 for a, b in zip(data[::2], data[1::2] + b"\x00"))
            & 0xFFFFFFFF
        )
        x = (x >> 16) + (x & 0xFFFF)
        x = (x >> 16) + (x & 0xFFFF)
        return (~x & 0xFFFF).to_bytes(2, "little")

    def ping(self, addr, timeout=1, count=2):
        for _ in range(count):
            try:
                sequence_number = random.randrange(0, 65536)
                packet_size = 64 - 8
                checksum = 0
                header = struct.pack(
                    "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, sequence_number
                )
                pad_bytes = []
                start_val = 0x42
                for i in range(start_val, start_val + packet_size):
                    pad_bytes += [(i & 0xFF)]  # Keep chars in the 0-255 range

                data = bytearray(pad_bytes)
                checksum = self.calculate_checksum(header + data)
                header = struct.pack(
                    "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, sequence_number
                )

                packet = header + data

                self.conn.sendto(packet, (addr, 1))
                start = time.time()
                while select.select(
                    [self.conn], [], [], max(0, start + timeout - time.time())
                )[0]:
                    packet, host = self.conn.recvfrom(65536)
                    icmp_header_raw = packet[20:28]
                    icmp_header = self.header2dict(
                        names=["type", "code", "checksum", "packet_id", "seq_number"],
                        struct_format="!BBHHH",
                        data=icmp_header_raw,
                    )
                    if (
                        icmp_header["type"] == ICMP_ECHOREPLY
                        and icmp_header["packet_id"] == self.own_id
                        and icmp_header["seq_number"] == sequence_number
                    ):
                        return time.time() - start
            except Exception as e:
                pass

    def ping6(self, addr, timeout=1, count=3):
        for _ in range(count):
            try:
                sequence_number = random.randrange(-32768, 32767)
                packet_size = 64 - 8
                checksum = 0
                header = struct.pack(
                    "!BbHHh", ICMP_ECHO_IPV6, 0, checksum, self.own_id, sequence_number
                )
                pad_bytes = []
                start_val = 0x42
                for i in range(start_val, start_val + packet_size):
                    pad_bytes += [(i & 0xFF)]  # Keep chars in the 0-255 range

                data = bytearray(pad_bytes)
                checksum = self.calculate_checksum(header + data)
                header = struct.pack(
                    "!BbHHh", ICMP_ECHO_IPV6, 0, checksum, self.own_id, sequence_number
                )

                packet = header + data

                self.conn6.sendto(packet, (addr, 58, 0, 0))
                start = time.time()
                while select.select(
                    [self.conn6], [], [], max(0, start + timeout - time.time())
                )[0]:
                    packet, host = self.conn6.recvfrom(65536)
                    icmp_header_raw = packet[0:8]
                    icmp_header = self.header2dict(
                        names=["type", "code", "checksum", "packet_id", "seq_number"],
                        struct_format="!BBHHH",
                        data=icmp_header_raw,
                    )
                    if (
                        icmp_header["type"] == ICMP_ECHO_IPV6_REPLY
                        and icmp_header["packet_id"] == self.own_id
                        and icmp_header["seq_number"] == sequence_number
                    ):
                        return time.time() - start
            except Exception as e:
                pass

    def header2dict(self, names, struct_format, data):
        """
        Unpack the raw received IP and ICMP header informations to a dict
        """
        unpacked_data = struct.unpack(struct_format, data)
        return dict(list(zip(names, unpacked_data)))

    def calculate_checksum(self, source_string):
        """
        A port of the functionality of in_cksum() from ping.c
        Ideally this would act on the string as a series of 16-bit ints (host
        packed), but this works.
        Network data is big-endian, hosts are typically little-endian
        """
        countTo = (int(len(source_string) / 2)) * 2
        my_sum = 0
        count = 0

        # Handle bytes in pairs (decoding as short ints)
        loByte = 0
        hiByte = 0
        while count < countTo:
            if sys.byteorder == "little":
                loByte = source_string[count]
                hiByte = source_string[count + 1]
            else:
                loByte = source_string[count + 1]
                hiByte = source_string[count]
            try:  # For Python3
                my_sum = my_sum + (hiByte * 256 + loByte)
            except:  # For Python2
                my_sum = my_sum + (ord(hiByte) * 256 + ord(loByte))
            count += 2

        # Handle last byte if applicable (odd-number of bytes)
        # Endianness should be irrelevant in this case
        if countTo < len(source_string):  # Check for odd length
            loByte = source_string[len(source_string) - 1]
            try:  # For Python3
                my_sum += loByte
            except:  # For Python2
                my_sum += ord(loByte)

        my_sum &= 0xFFFFFFFF  # Truncate sum to 32 bits (a variance from ping.c,
        # which uses signed ints, but overflow is unlikely
        # in ping)

        my_sum = (my_sum >> 16) + (my_sum & 0xFFFF)  # Add high 16 and low 16 bits
        my_sum += my_sum >> 16  # Add carry from above, if any
        answer = ~my_sum & 0xFFFF  # Invert & truncate to 16 bits
        answer = socket.htons(answer)

        return answer

    def close(self):
        self.conn.shutdown(socket.SHUT_RDWR)
        self.conn6.shutdown(socket.SHUT_RDWR)
        self.conn.close()
        self.conn6.close()


if __name__ == "__main__":
    p = Ping()
    res1 = p.ping("8.8.8.8")
    res2 = p.ping6("2001:4860:4860::8888")
    print("Ping result", res1, res2)
