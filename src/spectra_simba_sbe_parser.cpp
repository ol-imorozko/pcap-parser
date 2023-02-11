#include <ios>
#include <iostream>

#include "include/spectra_simba_sbe_parser.h"

namespace packet_parse::spectra_simba::sbe {

RawProto HeaderParser::Parse(std::ifstream& file, std::streamsize& packet_size,
                             [[maybe_unused]] RawProto raw_proto) const {
  Header p;
  RawProto next_proto = p.Parse(file, packet_size);

  root_block_size_ = p.GetRootBlockSize();

  return next_proto;
}

RawProto RootBlockParser::Parse(std::ifstream& file,
                                std::streamsize& packet_size,
                                [[maybe_unused]] RawProto raw_proto) const {
  auto proto = static_cast<MessageType>(raw_proto);

  switch (proto) {
    default:
      throw UnknownProto(raw_proto);
  }
}

RawProto MessageParser::Parse(std::ifstream& file, std::streamsize& packet_size,
                              [[maybe_unused]] RawProto raw_proto) const {
  HeaderParser hp;
  RawProto next_proto = HandleParser(hp, file, packet_size, raw_proto);

  auto root_block_size = static_cast<std::streamsize>(hp.GetRootBlockSize());

  packet_size -= root_block_size;

  RootBlockParser rbp;
  return HandleParser(rbp, file, root_block_size, next_proto);
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
