#include <arpa/inet.h>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>

#include "include/l3_parser.h"

namespace packet_parse {

void PrintIpHeader(const IpHeader& header) {
  std::cout << "IP header:" << '\n';
  std::cout << "  Version: " << (header.version_and_header_length >> 4) << '\n';
  std::cout << "  Header length: "
            << ((header.version_and_header_length & 0x0F) * 4) << " bytes"
            << '\n';
  std::cout << "  DSCP: " << (header.dscp_and_ecn >> 2) << '\n';
  std::cout << "  ECN: " << (header.dscp_and_ecn & 0x03) << '\n';
  std::cout << "  Total length: " << header.total_length << " bytes" << '\n';
  std::cout << "  Identification: 0x" << std::hex << std::setfill('0')
            << std::setw(4) << header.identification << std::dec << '\n';
  std::cout << "  Flags: " << ((header.flags_and_fragment_offset >> 13) & 0x07)
            << '\n';
  std::cout << "  Fragment offset: "
            << (header.flags_and_fragment_offset & 0x1FFF) << '\n';
  std::cout << " TTL: " << (int)header.ttl << '\n';
  std::cout << " Protocol: " << (int)header.protocol << '\n';
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

RawProto L3Parser::ParseIp(std::ifstream& file, size_t& packet_size) {
  IpHeader header{};

  if (packet_size < kIpHeaderSize)
    throw NotEnoughData("Ip", kIpHeaderSize, packet_size);

  file.read(reinterpret_cast<char*>(&header), kIpHeaderSize);

  if (!file) {
    packet_size = 0;
    throw EoF("Ip", kIpHeaderSize, file.gcount());
  }

  // Cause the data comes in a network byte order
  header.total_length = ntohs(header.total_length);
  header.identification = ntohs(header.identification);
  header.flags_and_fragment_offset = ntohs(header.flags_and_fragment_offset);
  header.header_checksum = ntohs(header.header_checksum);
  header.source_address = ntohl(header.source_address);
  header.destination_address = ntohl(header.destination_address);

  PrintIpHeader(header);

  packet_size -= kIpHeaderSize;
  return static_cast<RawProto>(header.protocol);
}

RawProto L3Parser::Parse(std::ifstream& file, size_t& packet_size,
                         RawProto raw_proto) {
  auto proto = static_cast<Proto>(raw_proto);

  switch (proto) {
    case Proto::kIp:
      return ParseIp(file, packet_size);
    default:
      throw UnknownProto(raw_proto);
  }
}

}  // namespace packet_parse
