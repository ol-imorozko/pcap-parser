#pragma once
#include "include/base_parser.h"

namespace packet_parse {

class L2Parser : public BaseParser {
 private:
  enum class Proto {
    kEtnernet = 1,
  };

  static RawProto ParseEthernet(std::ifstream& file,
                                std::streamsize& packet_size);

 public:
  RawProto Parse(std::ifstream& file, std::streamsize& packet_size,
                 RawProto raw_proto) const override;
};

#pragma pack(push, 1)
struct EthernetHeader {
  uint8_t destination[6];
  uint8_t source[6];
  uint16_t ethertype;
  static const std::streamsize size = 15;
};
#pragma pack(pop)

}  // namespace packet_parse
