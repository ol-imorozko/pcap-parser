#pragma once
#include <arpa/inet.h>
#include <iomanip>
#include <iostream>

#include "include/base_parser.h"

namespace packet_parse {

class L3Parser : public BaseParser {
 private:
  enum class Proto {
    kIp = 0x800,
  };

 public:
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) const override;
};

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
  constexpr static const char name[] = "IP";
};
#pragma pack(pop)

class Ip : public Protocol<IpHeader, IpHeader::name> {
 private:
  void Transform(IpHeader& header) override;

  RawProto GetNextProto(const IpHeader& header) override {
    return static_cast<RawProto>(header.protocol);
  }

  ServiceDataPtr Operation(const IpHeader& header,
                           ServiceDataPtr data) override;
};

}  // namespace packet_parse
