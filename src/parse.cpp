#include <cstring>
#include <fstream>
#include <iostream>

#include "include/pcap_headers.h"
#include "include/pcap_headers_helper.h"

constexpr size_t kMaxPacketSize = 65535;  // FIXME: this is snaplen?

int main(int argc, char* argv[]) {
  // Check if the file name is provided
  if (argc < 2) {
    std::cout << "Usage: pcap_parser <file_name>" << std::endl;
    return 0;
  }

  // Open the file
  std::ifstream file(argv[1], std::ios::in | std::ios::binary);
  if (!file) {
    std::cout << "Failed to open the file" << std::endl;
    return 0;
  }

  // Read raw PCAP file header
  PcapFileHeader raw_file_header{};
  file.read(reinterpret_cast<char*>(&raw_file_header), sizeof(PcapFileHeader));

  PcapHeadersHelper headers_helper(raw_file_header.magic_number);

  // Check if it's a PCAP file
  if (!headers_helper.FileValid()) {
    std::cout << "Not a PCAP file" << std::endl;
    return 0;
  }

  // Transfrorm raw PCAP file header according to endianness
  PcapFileHeader file_header =
      headers_helper.TransfrormRawFileHeader(raw_file_header);
  PcapHeadersHelper::PrintPcapFileHeader(file_header);

  // Read PCAP packets
  while (file.good()) {
    // Read PCAP packet header
    PcapPacketHeader raw_packet_header{};
    file.read(reinterpret_cast<char*>(&raw_packet_header),
              sizeof(PcapPacketHeader));

    // Transfrorm raw PCAP packet header according to endianness
    PcapPacketHeader packet_header =
        headers_helper.TransfrormRawPacketHeader(raw_packet_header);
    PcapHeadersHelper::PrintPcapPacketHeader(packet_header);

    // Check if it's the end of file
    if (!file.good())
      break;

    // Read packet data
    uint8_t packet_data[kMaxPacketSize];
    memset(packet_data, 0, kMaxPacketSize);
    file.read(reinterpret_cast<char*>(packet_data), packet_header.incl_len);

    // Do something with the packet data
    // ...
  }

  // Close the file
  file.close();

  return 0;
}
