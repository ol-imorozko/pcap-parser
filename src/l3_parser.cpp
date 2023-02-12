#include <array>
#include <cstdint>

#include "include/base_parser.h"
#include "include/l3_parser.h"

namespace packet_parse {

ServiceDataPtr L3Parser::Parse(Stream& packet, std::streamsize& packet_size,
                               ServiceDataPtr data) const {
  auto proto = static_cast<Proto>(data->proto);

  switch (proto) {
    case Proto::kIp: {
      Ip p;
      return p.Parse(packet, packet_size, std::move(data));
    }
    default:
      throw UnknownProto(data->proto);
  }
}

void Ip::Transform(IpHeader& header) {
  // Cause the data comes in a network byte order
  // We don't have to do this for source and destination adresses,
  // case we actually want them in network byte order in order
  // to print them via inet_ntop function.
  header.total_length = ntohs(header.total_length);
  header.identification = ntohs(header.identification);
  header.flags_and_fragment_offset = ntohs(header.flags_and_fragment_offset);
  header.header_checksum = ntohs(header.header_checksum);
}

ServiceDataPtr Ip::Operation(const IpHeader& header, ServiceDataPtr data) {
  std::cout << "IP header:" << '\n';
  std::cout << "  Version: " << (header.version_and_header_length >> 4) << '\n';
  std::cout << "  Header length: "
            << ((header.version_and_header_length & 0x0F) * 4) << " bytes"
            << '\n';
  std::cout << "  DSCP: " << (header.dscp_and_ecn >> 2) << '\n';
  std::cout << "  ECN: " << (header.dscp_and_ecn & 0x03) << '\n';
  std::cout << "  Total length: " << header.total_length << " bytes" << '\n';
  std::cout << "  Identification: 0x" << std::hex << std::setfill('0')
            << std::setw(4) << header.identification << '\n';
  std::cout << "  Flags: " << ((header.flags_and_fragment_offset >> 13) & 0x07)
            << std::dec << '\n';
  std::cout << "  Fragment offset: "
            << (header.flags_and_fragment_offset & 0x1FFF) << '\n';
  std::cout << " TTL: " << static_cast<int>(header.ttl) << '\n';
  std::cout << " Protocol: " << static_cast<int>(header.protocol) << '\n';
  std::cout << " Header checksum: 0x" << std::hex << std::setfill('0')
            << std::setw(4) << header.header_checksum << std::dec << '\n';

  char source_address_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &header.source_address, source_address_str,
            INET_ADDRSTRLEN);

  std::cout << " Source address: " << source_address_str << '\n';

  char dest_address_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &header.destination_address, dest_address_str,
            INET_ADDRSTRLEN);

  std::cout << " Destination address: " << dest_address_str << '\n';

  return data;
}

}  // namespace packet_parse
