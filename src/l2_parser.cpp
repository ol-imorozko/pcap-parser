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
              << static_cast<int>(header.destination[i]);
    if (i != 5)
      std::cout << ":";
  }

  std::cout << "\n  Source: ";

  for (int i = 0; i < 6; i++) {
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<int>(header.source[i]);
    if (i != 5)
      std::cout << ":";
  }

  std::cout << "\n  EtherType: 0x" << std::hex << std::setfill('0')
            << std::setw(4) << header.ethertype << std::dec << '\n';
}

RawProto L2Parser::ParseEthernet(std::ifstream& file,
                                 std::streamsize& packet_size) {
  EthernetHeader header{};

  if (packet_size < EthernetHeader::size)
    throw NotEnoughData("Ethernet", EthernetHeader::size, packet_size);

  file.read(reinterpret_cast<char*>(&header), EthernetHeader::size);
  /* file.read(reinterpret_cast<char*>(&header), 20); */

  if (file.eof()) {
    packet_size = 0;
    throw EoF("Ethernet", EthernetHeader::size, file.gcount());
  }

  // Cause the data comes in a network byte order
  header.ethertype = ntohs(header.ethertype);

  PrintEthernetHeader(header);

  packet_size -= EthernetHeader::size;
  return static_cast<RawProto>(header.ethertype);
}

RawProto L2Parser::Parse(std::ifstream& file, std::streamsize& packet_size,
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
