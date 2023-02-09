#pragma once
#include "include/base_parser.h"

namespace packet_parse {

class L4Parser : public BaseParser {
 private:
  enum class Proto {
    kUDP = 17,
  };

  static RawProto ParseUDP(std::ifstream& file, size_t& packet_size);

 public:
  RawProto Parse(std::ifstream& file, size_t& packet_size,
                 RawProto raw_proto) override;
};

constexpr int kUDPHeaderSize = 8;

#pragma pack(push, 1)
struct UDPHeader {
  uint16_t source_port;
  uint16_t destination_port;
  uint16_t length;
  uint16_t checksum;
};
#pragma pack(pop)

}  // namespace packet_parse
