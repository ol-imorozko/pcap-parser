#pragma once
#include <arpa/inet.h>
#include <iomanip>
#include <iostream>
#include <utility>
#include "include/base_parser.h"

namespace packet_parse {

class L2Parser : public BaseParser {
 private:
  enum class Proto {
    kEtnernet = 1,
  };

 public:
  RawProto Parse(std::ifstream& file, std::streamsize& packet_size,
                 RawProto raw_proto) const override;
};

#pragma pack(push, 1)
struct EthernetHeader {
  uint8_t destination[6];
  uint8_t source[6];
  uint16_t ethertype;
  constexpr static const char name[] = "Ethernet";
};
#pragma pack(pop)

class Ethernet : public Protocol<EthernetHeader, EthernetHeader::name> {
 private:
  void Transform(EthernetHeader& header) override {
    // Cause the data comes in a network byte order
    header.ethertype = ntohs(header.ethertype);
  }

  RawProto GetNextProto(const EthernetHeader& header) override {
    return static_cast<RawProto>(header.ethertype);
  }

  void Operation(const EthernetHeader& header) override;
};

}  // namespace packet_parse
