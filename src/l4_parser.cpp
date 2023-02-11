#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>

#include "include/l4_parser.h"

namespace packet_parse {

RawProto L4Parser::Parse(std::ifstream& file, std::streamsize& packet_size,
                         RawProto raw_proto) const {
  auto proto = static_cast<Proto>(raw_proto);

  switch (proto) {
    case Proto::kUDP: {
      UDP p;
      return p.Parse(file, packet_size);
    }
    case Proto::kICMP: {
      ICMP p;
      return p.Parse(file, packet_size);
    }
    default:
      throw UnknownProto(raw_proto);
  }
}

}  // namespace packet_parse
