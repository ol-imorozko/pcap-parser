#pragma once
#include <arpa/inet.h>
#include <iomanip>
#include <iostream>

#include "include/base_parser.h"

namespace packet_parse {

class L4Parser : public BaseParser {
 private:
  enum class Proto {
    kUDP = 17,
    kICMP = 1,
  };

 public:
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) const override;
};

#pragma pack(push, 1)
struct UDPHeader {
  uint16_t source_port;
  uint16_t destination_port;
  uint16_t length;
  uint16_t checksum;
  constexpr static const char name[] = "UDP";
};

struct ICMPHeader {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t sequence_number;
  constexpr static const char name[] = "ICMP";
};
#pragma pack(pop)

class UDP : public Protocol<UDPHeader, UDPHeader::name> {
 private:
  void Transform(UDPHeader& header) override;

  ServiceDataPtr Operation(const UDPHeader& header,
                           ServiceDataPtr data) override;
};

class ICMP : public Protocol<ICMPHeader, ICMPHeader::name> {
 private:
  void Transform(ICMPHeader& header) override;

  ServiceDataPtr Operation(const ICMPHeader& header,
                           ServiceDataPtr data) override;
};
}  // namespace packet_parse
