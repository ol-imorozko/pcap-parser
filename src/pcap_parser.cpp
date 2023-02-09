#include <cstring>
#include <fstream>
#include <iostream>

#include "include/base_parser.h"
#include "include/l2_parser.h"
#include "include/l3_parser.h"
#include "include/pcap_headers.h"

template <class T>
T ReadRawHeader(std::ifstream& file) {
  T raw_header{};
  file.read(reinterpret_cast<char*>(&raw_header), sizeof(T));
  return raw_header;
}

//Usually Original Packet Length is equal to the Captured Packet Length.
//
//In rare cases the original packet length could be greater then the
//captured one, cause the reciever could say "I want to capture bytes till
//the 100'th byte" (this indicates by the SnapLen field in file header),
//and if the original packet length was greater than 100, it will be
//stripped.
//
//The situation where original lesser than captured shouldn't be possible:
//From PCAP specification:
//Captured Packet Length:
// - It will be the minimum value among the Original Packet Length and the
//   snapshot length for the interface (SnapLen, defined in Figure 1).
//
//However, one could find a pcap file where this is not the case:
//https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dvb-ci_2.pcap
//
//In this case, we need to advance the position in the file by the number
//of remaining bytes.
packet_parse::RawProto RunParserAndTrim(packet_parse::BaseParser& parser,
                                        std::ifstream& file, size_t& len,
                                        packet_parse::RawProto proto,
                                        size_t bytes_to_trim) {
  packet_parse::RawProto next_proto =
      packet_parse::HandleParser(parser, file, len, proto);

  if (len == 0 && file)
    file.seekg(static_cast<long>(bytes_to_trim), std::ios::cur);

  return next_proto;
}

void ParsePacket(std::ifstream& file,
                 pcap_parse::PacketHeader pcap_packet_header,
                 uint32_t initial_proto) {
  size_t real_packet_length = pcap_packet_header.GetRealPacketLength();
  size_t captured_packet_length = pcap_packet_header.GetCapturedPacketLength();
  size_t bytes_to_trim = 0;

  if (captured_packet_length > real_packet_length)
    bytes_to_trim = captured_packet_length - real_packet_length;

  {
    packet_parse::L2Parser l2p;
    packet_parse::RawProto next_proto = RunParserAndTrim(
        l2p, file, real_packet_length,
        static_cast<packet_parse::RawProto>(initial_proto), bytes_to_trim);

    if (real_packet_length == 0)
      return;

    packet_parse::L3Parser l3p;
    next_proto = RunParserAndTrim(l3p, file, real_packet_length, next_proto,
                                  bytes_to_trim);

    if (real_packet_length == 0)
      return;
  }

  std::cerr << "Parsing ended but still " << real_packet_length
            << " bytes left. Ignore them." << std::endl;

  if (file)
    file.seekg(static_cast<long>(real_packet_length), std::ios::cur);
  if (file)
    file.seekg(static_cast<long>(bytes_to_trim), std::ios::cur);
}

void ParsePcapPackets(pcap_parse::FileHeader& file_header,
                      std::ifstream& file) {
  file_header.Print();

  // Read PCAP packets
  while (!file.eof()) {
    // Read raw PCAP packet header
    auto raw_packet_header = ReadRawHeader<pcap_parse::RawPacketHeader>(file);

    // Check if it's the end of file
    if (file.eof())
      break;

    // Get normal PCAP packet header
    pcap_parse::PacketHeader packet_header(raw_packet_header, file_header);

    packet_header.Print();

    ParsePacket(file, packet_header, file_header.GetLinkType());
  }
}

int main(int argc, char* argv[]) {
  // Check if the file name is provided
  if (argc != 2) {
    std::cerr << "Usage: pcap_parser <file_name>" << std::endl;
    return 0;
  }

  // Open the file
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
    ParsePcapPackets(file_header, file);
  } catch (const std::exception& e) {
    std::cerr << argv[1] << " is not a PCAP file" << std::endl;
  }

  // Close the file
  file.close();

  return 0;
}
