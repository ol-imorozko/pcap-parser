#include <array>
#include <cstdint>
#include <iostream>

#include "include/l2_parser.h"

namespace packet_parse {

ServiceDataPtr L2Parser::Parse(Stream& packet, std::streamsize& packet_size,
                               ServiceDataPtr data) const {
  auto proto = static_cast<Proto>(data->proto);

  switch (proto) {
    case Proto::kEtnernet: {
      Ethernet p;
      return p.Parse(packet, packet_size, std::move(data));
    }
    default:
      throw UnknownProto(data->proto);
  }
}

ServiceDataPtr Ethernet::Operation(const EthernetHeader& header,
                                   ServiceDataPtr data) {
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

  return data;
}

}  // namespace packet_parse
