#pragma once
#include "include/base_parser.h"

namespace packet_parse {

class L3Parser : public BaseParser {
 private:
  enum class Proto {
    kIp = 0x800,
  };

  static RawProto ParseIp(std::ifstream& file, size_t& packet_size);

 public:
  RawProto Parse(std::ifstream& file, size_t& packet_size,
                 RawProto raw_proto) override;
};

constexpr int kIpHeaderSize = 20;

#pragma pack(push, 1)
struct IpHeader {
  uint8_t version_and_header_length;
  uint8_t dscp_and_ecn;
  uint16_t total_length;
  uint16_t identification;
  uint16_t flags_and_fragment_offset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t header_checksum;
  uint32_t source_address;
  uint32_t destination_address;
};
#pragma pack(pop)

}  // namespace packet_parse
