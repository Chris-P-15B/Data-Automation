#!/usr/bin/env python
# v1.0 - written by Chris Perkins in 2019
# Convert "show monitor capture buffer dump" into format usable by text2pcap
# Based on ciscoText2pcap https://github.com/mad-ady/ciscoText2pcap

import sys, re

if __name__ == "__main__":
    # Parse command line parameters
    if len(sys.argv) != 3:
        print("Please specify source & destination files as parameters.")
        sys.exit(1)
    # Parse input file via regex
    try:
        with open(sys.argv[1]) as in_file:
            with open(sys.argv[2], 'w') as out_file:
                packet_start = 0
                for line in in_file:
                    # Regex to find valid blocks of hexadecimal
                    hex_dump = re.search(r"^[0-9A-F]+:\s+((?:[0-9A-F]+ ){1,4}) (.+)\n", line)
                    if hex_dump:
                        # Iterate through each block of hex & split into sets of 2 digits with spaces inbetween
                        char_list = hex_dump.group(1).split()
                        for chars in char_list:
                            packet_hex = ''
                            for i in range(1,len(chars),2):
                                packet_hex += f"{chars[i-1:i+1]} "
                            packet_hex = packet_hex.rstrip()
                            # Output packet as offset (8 hex digits) + hex string
                            out_file.write(f"{packet_start:08X} {packet_hex}\n")
                            packet_start += len(chars) // 2
                    else:
                        # End of packet
                        packet_start = 0
    except FileNotFoundError:
        print(f"Unable to open file {sys.argv[1]}")
        sys.exit(1)
    except OSError:
        print(f"Unable to write file {sys.argv[2]}")
        sys.exit(1)