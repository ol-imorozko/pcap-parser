#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>

#include "include/l2_parser.h"

namespace packet_parse {

void PrintEthernetHeader(const EthernetHeader& header) {
  std::cout << "Ethernet header:\n  Destination: ";

  for (int i = 0; i < 6; i++) {
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << (int)header.destination[i];
    if (i != 5)
      std::cout << ":";
  }

  std::cout << "\n  Source: ";

  for (int i = 0; i < 6; i++) {
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << (int)header.source[i];
    if (i != 5)
      std::cout << ":";
  }

  std::cout << "\n  EtherType: 0x" << std::hex << std::setfill('0')
            << std::setw(4) << header.etherType << std::dec << '\n';
}

RawProto L2Parser::ParseEthernet(std::ifstream& file, size_t& packet_size) {
  EthernetHeader header{};

  if (packet_size < kEthernetHeaderSize)
    throw NotEnoughData("Ethernet", kEthernetHeaderSize, packet_size);

  file.read(reinterpret_cast<char*>(&header), kEthernetHeaderSize);

  if (!file) {
    packet_size = 0;
    throw EoF("Ethernet", kEthernetHeaderSize, file.gcount());
  }

  // Cause the data comes in a network byte order
  header.etherType = ntohs(header.etherType);

  PrintEthernetHeader(header);

  packet_size -= kEthernetHeaderSize;
  return static_cast<RawProto>(header.etherType);
}

RawProto L2Parser::Parse(std::ifstream& file, size_t& packet_size,
                         RawProto raw_proto) {
  auto proto = static_cast<Proto>(raw_proto);

  switch (proto) {
    case Proto::kEtnernet:
      return ParseEthernet(file, packet_size);
    default:
      throw UnknownProto(raw_proto);
  }
}

}  // namespace packet_parse
