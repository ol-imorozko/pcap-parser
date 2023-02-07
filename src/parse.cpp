#include <cstring>
#include <fstream>
#include <iostream>

#include "include/pcap_headers.h"
#include "include/pcap_headers_helper.h"

constexpr size_t MAX_PACKET_SIZE = 65535; // FIXME: this is snaplen?

int main(int argc, char *argv[]) {
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
  PcapFileHeader rawFileHeader{};
  file.read(reinterpret_cast<char *>(&rawFileHeader), sizeof(PcapFileHeader));

  PcapHeadersHelper headersHelper(rawFileHeader.magic_number);

  // Check if it's a PCAP file
  if (!headersHelper.file_valid()) {
    std::cout << "Not a PCAP file" << std::endl;
    return 0;
  }

  // Transfrorm raw PCAP file header according to endianness
  PcapFileHeader fileHeader = headersHelper.transfrormRawFileHeader(rawFileHeader);
  PcapHeadersHelper::printPcapFileHeader(fileHeader);

  // Read PCAP packets
  while (file.good()) {
    // Read PCAP packet header
    PcapPacketHeader rawPacketHeader{};
    file.read(reinterpret_cast<char *>(&rawPacketHeader),
              sizeof(PcapPacketHeader));

    // Transfrorm raw PCAP packet header according to endianness
    PcapPacketHeader packetHeader =
        headersHelper.transfrormRawPacketHeader(rawPacketHeader);
    PcapHeadersHelper::printPcapPacketHeader(packetHeader);

    // Check if it's the end of file
    if (!file.good())
      break;

    // Read packet data
    uint8_t packetData[MAX_PACKET_SIZE];
    memset(packetData, 0, MAX_PACKET_SIZE);
    file.read(reinterpret_cast<char *>(packetData), packetHeader.incl_len);

    // Do something with the packet data
    // ...
  }

  // Close the file
  file.close();

  return 0;
}
