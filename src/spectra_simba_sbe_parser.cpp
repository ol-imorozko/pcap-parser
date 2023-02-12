#include <ios>
#include <iostream>

#include "include/spectra_simba_sbe_parser.h"

namespace packet_parse::spectra_simba::sbe {

RawProto HeaderParser::Parse(Stream& packet, std::streamsize& packet_size,
                             [[maybe_unused]] RawProto raw_proto) {
  Header p;
  RawProto next_proto = p.Parse(packet, packet_size);

  root_block_size_ = p.GetRootBlockSize();

  return next_proto;
}

RawProto RootBlockParser::Parse(Stream& packet, std::streamsize& packet_size,
                                [[maybe_unused]] RawProto raw_proto) {
  auto proto = static_cast<MessageType>(raw_proto);

  switch (proto) {
    default:
      throw UnknownProto(raw_proto);
  }
}

RawProto MessageParser::Parse(Stream& packet, std::streamsize& packet_size,
                              [[maybe_unused]] RawProto raw_proto) {
  HeaderParser hp;
  RawProto next_proto = HandleParser(hp, packet, packet_size, raw_proto);

  auto root_block_size = static_cast<std::streamsize>(hp.GetRootBlockSize());

  packet_size -= root_block_size;

  RootBlockParser rbp;
  return HandleParser(rbp, packet, root_block_size, next_proto);
}

void Header::Operation(const HeaderFormat& header) {
  std::cout << "SBE Message Header:\n";
  std::cout << "  The root part length of the message in bytes: "
            << header.block_length << '\n';
  std::cout << "  Message template identifier: " << header.template_id << '\n';
  std::cout << "  Message schema identifier: " << header.schema_id << '\n';
  std::cout << "  Message schema version: " << header.version << '\n';

  root_block_size_ = header.block_length;
}

}  // namespace packet_parse::spectra_simba::sbe
