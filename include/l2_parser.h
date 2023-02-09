#pragma once
#include "include/base_parser.h"

namespace packet_parse {

class L2Parser : public BaseParser {
 private:
  enum class Proto {
    kEtnernet = 1,
  };

  static RawProto ParseEthernet(std::ifstream& file, size_t& packet_size);

 public:
  RawProto Parse(std::ifstream& file, size_t& packet_size,
                 RawProto raw_proto) override;
};

constexpr int kEthernetHeaderSize = 14;

#pragma pack(push, 1)
struct EthernetHeader {
  uint8_t destination[6];
  uint8_t source[6];
  uint16_t ethertype;
};
#pragma pack(pop)

}  // namespace packet_parse
