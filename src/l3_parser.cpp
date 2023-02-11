#include <array>
#include <cstdint>

#include "include/l3_parser.h"

namespace packet_parse {

RawProto L3Parser::Parse(std::ifstream& file, std::streamsize& packet_size,
                         RawProto raw_proto) const {
  auto proto = static_cast<Proto>(raw_proto);

  switch (proto) {
    case Proto::kIp: {
      Ip p;
      return p.Parse(file, packet_size);
    }
    default:
      throw UnknownProto(raw_proto);
  }
}

}  // namespace packet_parse
