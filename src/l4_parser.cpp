#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>

#include "include/l4_parser.h"

namespace packet_parse {

void PrintUDPHeader(const UDPHeader& header) {
  std::cout << "UDP header:" << '\n';
  std::cout << "  Source port: " << header.source_port << '\n';
  std::cout << "  Destination port: " << header.destination_port << '\n';
  std::cout << "  Length: " << header.length << '\n';
  std::cout << "  Checksum: 0x" << std::hex << header.checksum << std::dec
            << '\n';
}

RawProto L4Parser::ParseUDP(std::ifstream& file, size_t& packet_size) {
  UDPHeader header{};

  if (packet_size < kUDPHeaderSize)
    throw NotEnoughData("UDP", kUDPHeaderSize, packet_size);

  file.read(reinterpret_cast<char*>(&header), kUDPHeaderSize);

  if (file.eof()) {
    packet_size = 0;
    throw EoF("UDP", kUDPHeaderSize, file.gcount());
  }

  // Cause the data comes in a network byte order
  header.source_port = ntohs(header.source_port);
  header.destination_port = ntohs(header.destination_port);
  header.length = ntohs(header.length);
  header.checksum = ntohs(header.checksum);

  PrintUDPHeader(header);

  packet_size -= kUDPHeaderSize;
  return 0;
}

void PrintICMPHeader(const ICMPHeader& header) {

  std::cout << "ICMP header:" << '\n';
  std::cout << "  Type: " << static_cast<int>(header.type) << '\n';
  std::cout << "  Code: " << static_cast<int>(header.code) << '\n';
  std::cout << "  Checksum: 0x" << std::hex << header.checksum << '\n';
  std::cout << "  Identifier: " << header.identifier << '\n';
  std::cout << "  Sequence number: " << header.sequence_number << std::dec
            << '\n';
}

RawProto L4Parser::ParseICMP(std::ifstream& file, size_t& packet_size) {
  ICMPHeader header{};

  if (packet_size < kICMPHeaderSize)
    throw NotEnoughData("ICMP", kICMPHeaderSize, packet_size);

  file.read(reinterpret_cast<char*>(&header), kICMPHeaderSize);

  if (!file) {
    packet_size = 0;
    throw EoF("ICMP", kICMPHeaderSize, file.gcount());
  }

  // Cause the data comes in a network byte order
  header.checksum = ntohs(header.checksum);
  header.identifier = ntohs(header.identifier);
  header.sequence_number = ntohs(header.sequence_number);

  PrintICMPHeader(header);

  packet_size -= kICMPHeaderSize;
  return 0;
}

RawProto L4Parser::Parse(std::ifstream& file, size_t& packet_size,
                         RawProto raw_proto) {
  auto proto = static_cast<Proto>(raw_proto);

  switch (proto) {
    case Proto::kUDP:
      return ParseUDP(file, packet_size);
    case Proto::kICMP:
      return ParseICMP(file, packet_size);
    default:
      throw UnknownProto(raw_proto);
  }
}

}  // namespace packet_parse
