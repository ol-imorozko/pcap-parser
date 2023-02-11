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
  RawProto Parse(std::ifstream& file, std::streamsize& packet_size,
                 RawProto raw_proto) const override;
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
  void Transform(IpHeader& header) override {
    // Cause the data comes in a network byte order
    // Cause the data comes in a network byte order
    // We don't have to do this for source and destination adresses,
    // case we actually want them in newtwork byte order in order
    // to print them via inet_ntop function.
    header.total_length = ntohs(header.total_length);
    header.identification = ntohs(header.identification);
    header.flags_and_fragment_offset = ntohs(header.flags_and_fragment_offset);
    header.header_checksum = ntohs(header.header_checksum);
  }

  RawProto GetNextProto(const IpHeader& header) override {
    return static_cast<RawProto>(header.protocol);
  }

  void Operation(const IpHeader& header) override {
    std::cout << "IP header:" << '\n';
    std::cout << "  Version: " << (header.version_and_header_length >> 4)
              << '\n';
    std::cout << "  Header length: "
              << ((header.version_and_header_length & 0x0F) * 4) << " bytes"
              << '\n';
    std::cout << "  DSCP: " << (header.dscp_and_ecn >> 2) << '\n';
    std::cout << "  ECN: " << (header.dscp_and_ecn & 0x03) << '\n';
    std::cout << "  Total length: " << header.total_length << " bytes" << '\n';
    std::cout << "  Identification: 0x" << std::hex << std::setfill('0')
              << std::setw(4) << header.identification << std::dec << '\n';
    std::cout << "  Flags: "
              << ((header.flags_and_fragment_offset >> 13) & 0x07) << '\n';
    std::cout << "  Fragment offset: "
              << (header.flags_and_fragment_offset & 0x1FFF) << '\n';
    std::cout << " TTL: " << static_cast<int>(header.ttl) << '\n';
    std::cout << " Protocol: " << static_cast<int>(header.protocol) << '\n';
    std::cout << " Header checksum: 0x" << std::hex << std::setfill('0')
              << std::setw(4) << header.header_checksum << '\n';

    char source_address_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &header.source_address, source_address_str,
              INET_ADDRSTRLEN);

    std::cout << " Source address: " << source_address_str << '\n';

    char dest_address_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &header.destination_address, dest_address_str,
              INET_ADDRSTRLEN);

    std::cout << " Destination address: " << dest_address_str << '\n';
  }
};

}  // namespace packet_parse
