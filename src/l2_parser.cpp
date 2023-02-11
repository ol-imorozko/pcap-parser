#include <array>
#include <cstdint>
#include <iostream>

#include "include/l2_parser.h"

namespace packet_parse {

RawProto L2Parser::Parse(std::ifstream& file, std::streamsize& packet_size,
                         RawProto raw_proto) const {
  auto proto = static_cast<Proto>(raw_proto);

  switch (proto) {
    case Proto::kEtnernet: {
      Ethernet p;
      return p.Parse(file, packet_size);
    }
    default:
      throw UnknownProto(raw_proto);
  }
}

void Ethernet::Operation(const EthernetHeader& header) {
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

}  // namespace packet_parse
