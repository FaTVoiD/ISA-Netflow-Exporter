# ISA project - Netflow v5 TCP Exporter

Author: Michal Belovec\
Login: xbelov04  

## Description

The program extracts information processes information from a PCAP file, agregates packets into flows and sends them onto a collector in Netflow v5 format. The agregation of packets into flows is based on 4 key values: source IP, destination IP, source port and destination port. If these values match, it means that the packets belong to the same flow.

The export mechanism uses timeout values (in seconds) to export flows. The timeouts specified are:
1. Active timeout - is determined by the time difference between the first packet of a flow and the currently processed packet. 
2. Inactive timeout - similar to active timeout, inactive timeout is determined by the time difference between the last packet of a flow and the currently processed packet.

When reaching the end of the PCAP file, all active flows are exported and the program ends.

The limit of flows sent to the collector in one packet is limited at 30.

## Compiling

The package contains a Makefile, so all you need to do to compile the code is type the `make` command.

## Running

The program accepts 5 types of arguments:
- `--help` - used to print out a quick guide
- `<host>:<port>` - "host" defines the IP address or hostname of the collector while "port" defines the port number of the collector. This argument is mandatory!
- `<file>.pcap` - defines the path to the processed PCAP file. This argument is mandatory!
- `[-a <value>]` - defines the active timeout duration. Optional argument. Default value is 60.
- `[-i <value>]` - defines the inactive timeout duration. Optional argument. Default value is 60.
The value for both timeouts is in seconds.

Example of running the program:  
`./p2nprobe localhost:1234 file.pcap`
or with specified timeouts:  
`./p2nprobe localhost:1234 file.pcap -a 45 -i 10`

## Known limitations

When the program is run with the ":" argument, it crashes. The program determines that this argument is the `<host>:<port>` argument. Sadly this issue was not uncovered in time to repair it before the deadline.

## List of files contained

p2nprobe.cpp - program implementation\
p2nprobe.h - header file for p2nprobe.cpp\
Makefile - used for building the project\
