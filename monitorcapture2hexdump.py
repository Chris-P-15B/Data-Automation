#!/usr/bin/env python
# (c) 2019, Chris Perkins
# Converts Cisco EPC "show monitor capture buffer dump" into format usable by text2pcap
# Use text2pcap -d -t "%Y-%m-%d %H:%M:%S." to convert output to PCAP whilst showing parsing info
# Based on ciscoText2pcap https://github.com/mad-ady/ciscoText2pcap

# v1.1 - added time stamp handling, converts into UTC
# v1.0 - initial release

import sys, re, pytz, datetime

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
                    # Regex to find timestamp, then manipulate into format text2pcap can use, as %z or %Z is failing
                    time_date = re.search(r"^(\d\d:\d\d:\d\d\.\d+) (\w+) ([\w ]+) : ", line)
                    if time_date:
                        # Use pytz to parse timezone, then make datetime object TZ aware & convert into UTC
                        try:
                            tz = pytz.timezone(time_date.group(2))
                            dt = datetime.datetime.strptime(f"{time_date.group(3).rstrip()} {time_date.group(1).rstrip()}",
                                "%b %d %Y %H:%M:%S.%f")
                            dt = dt.replace(tzinfo=tz)
                            dt = dt.astimezone(tz=datetime.timezone.utc)
                            out_file.write(f"{dt.strftime('%Y-%m-%d %H:%M:%S.%f')}\n")
                        except IndexError:
                            pass
                        # Continue to next line in input file
                        continue
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