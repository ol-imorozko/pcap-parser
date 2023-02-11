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
  RawProto Parse(std::ifstream& file, std::streamsize& packet_size,
                 RawProto raw_proto) const override;
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
  void Transform(UDPHeader& header) override {
    // Cause the data comes in a network byte order
    header.source_port = ntohs(header.source_port);
    header.destination_port = ntohs(header.destination_port);
    header.length = ntohs(header.length);
    header.checksum = ntohs(header.checksum);
  }

  void Operation(const UDPHeader& header) override {
    std::cout << "UDP header:" << '\n';
    std::cout << "  Source port: " << header.source_port << '\n';
    std::cout << "  Destination port: " << header.destination_port << '\n';
    std::cout << "  Length: " << header.length << '\n';
    std::cout << "  Checksum: 0x" << std::hex << header.checksum << std::dec
              << '\n';
  }
};

class ICMP : public Protocol<ICMPHeader, ICMPHeader::name> {
 private:
  void Transform(ICMPHeader& header) override {
    // Cause the data comes in a network byte order
    header.checksum = ntohs(header.checksum);
    header.identifier = ntohs(header.identifier);
    header.sequence_number = ntohs(header.sequence_number);
  }

  void Operation(const ICMPHeader& header) override {
    std::cout << "ICMP header:" << '\n';
    std::cout << "  Type: " << static_cast<int>(header.type) << '\n';
    std::cout << "  Code: " << static_cast<int>(header.code) << '\n';
    std::cout << "  Checksum: 0x" << std::hex << header.checksum << '\n';
    std::cout << "  Identifier: " << header.identifier << '\n';
    std::cout << "  Sequence number: " << header.sequence_number << std::dec
              << '\n';
  }
};
}  // namespace packet_parse
