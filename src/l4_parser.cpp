#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>

#include "include/l4_parser.h"

namespace packet_parse {

RawProto L4Parser::Parse(std::ifstream& file, std::streamsize& packet_size,
                         RawProto raw_proto) const {
  auto proto = static_cast<Proto>(raw_proto);

  switch (proto) {
    case Proto::kUDP: {
      UDP p;
      return p.Parse(file, packet_size);
    }
    case Proto::kICMP: {
      ICMP p;
      return p.Parse(file, packet_size);
    }
    default:
      throw UnknownProto(raw_proto);
  }
}

void UDP::Transform(UDPHeader& header) {
  // Cause the data comes in a network byte order
  header.source_port = ntohs(header.source_port);
  header.destination_port = ntohs(header.destination_port);
  header.length = ntohs(header.length);
  header.checksum = ntohs(header.checksum);
}

void UDP::Operation(const UDPHeader& header) {
  std::cout << "UDP header:" << '\n';
  std::cout << "  Source port: " << header.source_port << '\n';
  std::cout << "  Destination port: " << header.destination_port << '\n';
  std::cout << "  Length: " << header.length << '\n';
  std::cout << "  Checksum: 0x" << std::hex << header.checksum << std::dec
            << '\n';
}

void ICMP::Transform(ICMPHeader& header) {
  // Cause the data comes in a network byte order
  header.checksum = ntohs(header.checksum);
  header.identifier = ntohs(header.identifier);
  header.sequence_number = ntohs(header.sequence_number);
}

void ICMP::Operation(const ICMPHeader& header) {
  std::cout << "ICMP header:" << '\n';
  std::cout << "  Type: " << static_cast<int>(header.type) << '\n';
  std::cout << "  Code: " << static_cast<int>(header.code) << '\n';
  std::cout << "  Checksum: 0x" << std::hex << header.checksum << '\n';
  std::cout << "  Identifier: " << header.identifier << '\n';
  std::cout << "  Sequence number: " << header.sequence_number << std::dec
            << '\n';
}
}  // namespace packet_parse
