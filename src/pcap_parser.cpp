#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>

#include "include/base_parser.h"
#include "include/l2_parser.h"
#include "include/l3_parser.h"
#include "include/l4_parser.h"
#include "include/pcap_headers.h"
#include "include/spectra_simba_l1_parser.h"

template <class T>
T ReadRawHeader(packet_parse::Stream& data) {
  T raw_header{};
  data.read(reinterpret_cast<char*>(&raw_header), sizeof(T));
  return raw_header;
}

// Usually Original Packet Length is equal to the Captured Packet Length.
//
// In rare cases the original packet length could be greater than the
// captured one, because the reciever could say "I want to capture bytes till
// the 100'th byte" (this is indicated by by the SnapLen field in file header),
// and if the original packet length was greater than 100, it will be
// stripped.
//
// The situation where the original packet length is lesser than the captured one
// shouldn't be possible. From PCAP specification:
// Captured Packet Length:
//  - It will be the minimum value among the Original Packet Length and the
//    snapshot length for the interface (SnapLen, defined in Figure 1).
//
// However, one could find a pcap file where this is not the case:
// https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dvb-ci_2.pcap
//
// In this case, we need to advance the position in the file by the number
// of remaining bytes.
packet_parse::ServiceDataPtr RunParserAndTrim(
    const packet_parse::BaseParser& parser, packet_parse::Stream& packet,
    std::streamsize& len, packet_parse::ServiceDataPtr data,
    size_t bytes_to_trim) {
  packet_parse::ServiceDataPtr next_data =
      packet_parse::HandleParser(parser, packet, len, std::move(data));

  if (len == 0)
    packet_parse::TrimBytes(packet,
                            static_cast<std::streamsize>(bytes_to_trim));

  return next_data;
}

bool RunAllParsers(packet_parse::Stream& packet, std::streamsize& len,
                   uint32_t initial_proto, size_t bytes_to_trim) {

  packet_parse::ServiceDataPtr next_data =
      std::make_unique<packet_parse::ServiceData>(initial_proto);

  packet_parse::L2Parser l2p;
  next_data =
      RunParserAndTrim(l2p, packet, len, std::move(next_data), bytes_to_trim);

  if (len == 0)
    return true;

  packet_parse::L3Parser l3p;
  next_data =
      RunParserAndTrim(l3p, packet, len, std::move(next_data), bytes_to_trim);

  if (len == 0)
    return true;

  packet_parse::L4Parser l4p;
  next_data =
      RunParserAndTrim(l4p, packet, len, std::move(next_data), bytes_to_trim);

  if (len == 0)
    return true;

  packet_parse::spectra_simba::L1Parser ss_l1p;
  next_proto = RunParserAndTrim(ss_l1p, file, len, next_proto, bytes_to_trim);

  if (len == 0)
    return true;

  return false;
}

void ParsePacket(packet_parse::Stream& packet,
                 const pcap_parse::PacketHeader& pcap_packet_header,
                 uint32_t initial_proto) {
  size_t len = pcap_packet_header.GetRealPacketLength();
  size_t captured = pcap_packet_header.GetCapturedPacketLength();
  size_t bytes_to_trim = 0;

  if (captured > len)
    bytes_to_trim = captured - len;

  auto packet_len = static_cast<std::streamsize>(len);

  if (!RunAllParsers(packet, packet_len, initial_proto, bytes_to_trim)) {
    std::cerr << "Parsing ended but " << packet_len << " bytes left:\n";
    packet_parse::HexdumpBytes(packet, packet_len);
    packet_parse::TrimBytes(packet,
                            static_cast<std::streamsize>(bytes_to_trim));
  }
}

void ParsePcapPackets(packet_parse::Stream& data,
                      const pcap_parse::FileHeader& file_header) {
  file_header.Print();

  // Read PCAP packets
  while (!data.eof()) {
    // Read raw PCAP packet header
    auto raw_packet_header = ReadRawHeader<pcap_parse::RawPacketHeader>(data);

    if (data.eof())
      break;

    // Get normal PCAP packet header
    pcap_parse::PacketHeader packet_header(raw_packet_header, file_header);

    packet_header.Print();

    ParsePacket(data, packet_header, file_header.GetLinkType());
  }
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: pcap_parser <file_name>" << std::endl;
    return 0;
  }

  std::ifstream file(argv[1], std::ios::in | std::ios::binary);
  if (!file) {
    std::cerr << "Failed to open the file" << std::endl;
    return 0;
  }

  // Read raw PCAP file header
  auto raw_file_header = ReadRawHeader<pcap_parse::RawFileHeader>(file);
  if (!file) {
    std::cerr << "Cannot read PCAP file header" << std::endl;
    return 0;
  }

  // Get normal PCAP file header and parse packets
  try {
    pcap_parse::FileHeader file_header(raw_file_header);
    ParsePcapPackets(file, file_header);
  } catch (const std::exception& e) {
    std::cerr << e.what() << std::endl;
  }

  file.close();

  return 0;
}
