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

}  // namespace packet_parse
