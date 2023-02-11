#pragma once
#include "include/base_parser.h"

namespace packet_parse {

class L4Parser : public BaseParser {
 private:
  enum class Proto {
    kUDP = 17,
    kICMP = 1,
  };

  static RawProto ParseUDP(std::ifstream& file, std::streamsize& packet_size);

  static RawProto ParseICMP(std::ifstream& file, std::streamsize& packet_size);

 public:
  RawProto Parse(std::ifstream& file, std::streamsize& packet_size,
                 RawProto raw_proto) override;
};

constexpr int kUDPHeaderSize = 8;
constexpr int kICMPHeaderSize = 8;

#pragma pack(push, 1)
struct UDPHeader {
  uint16_t source_port;
  uint16_t destination_port;
  uint16_t length;
  uint16_t checksum;
};

struct ICMPHeader {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t sequence_number;
};
#pragma pack(pop)

}  // namespace packet_parse
