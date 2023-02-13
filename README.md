# pcap-parser
This is pcap parser without third-party libraries written in pure C++.

This version uses C++20 and performs Simba-Spectra protocol parsing

# Limitations
- Supported Schema: FIX5SP2 (version 1, ID 19780)
- Fragmented packets are not supported
    - Parsing performs only on whole Snapshot and Incremental packets
    
      Since there is no straightforward way to determine whether the Incremental packet
      is going to be whole or the last fragment, we still parse them, but hope for the best.
- Assumptions:
    - PC uses little-endian
    - Packets coming to UDP port 20081-20086 are Spectra-Simba packets
    - Packets coming not to UDP port 20081-20086 aren't Spectra-Simba packets
# Build
- Clone this repository
- Call `make`

# Usage
`./pcap-parser /path/to/file.pcap`

In order to save output in file, use
`./pcap-parser /path/to/file.pcap &> your_file`

