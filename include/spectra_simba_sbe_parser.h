#pragma once

#include "include/base_parser.h"

namespace packet_parse::spectra_simba::sbe {

class HeaderParser : public BaseParser {
 private:
  // Usually we shouldn't be able to
  // change object state via the Parse() function.
  // This function parses the header on a partucular layer in the
  // layered structure of a packet, and after that another Parse()
  // function is called from the upper layer and so on.
  // We don't need to pass data from the bottom level to the top
  // (except the next protocol, of course), so we restrict that.
  //
  // However, an Incremental packet of Simba Spectra could contain
  // many SBE messages. If we will do parsing as before and some
  // message type is unsupported, the Parse() function will throw
  // UnknownProto exception, as expected, and all remaining data
  // of a packet will be hexdumped.
  // But we only want to dump data from the current SBE message
  // and continue parsing the following ones. So we actually
  // need a way to get the size of the following root block from
  // the HeaderParser, hence this is a mutable field.
  //
  // You can see that logic being applied in MessageParser::Parse()
  mutable size_t root_block_size_{};

 public:
  RawProto Parse(Stream& packet, std::streamsize& packet_size,
                 RawProto raw_proto) override;

  size_t GetRootBlockSize() const { return root_block_size_; }
};

class RootBlockParser : public BaseParser {
 private:
  enum class MessageType {};

 public:
  RawProto Parse(Stream& packet, std::streamsize& packet_size,
                 RawProto raw_proto) override;
};

class MessageParser : public BaseParser {
 public:
  RawProto Parse(Stream& packet, std::streamsize& packet_size,
                 RawProto raw_proto) override;
};

#pragma pack(push, 1)
struct HeaderFormat {
  uint16_t block_length;
  uint16_t template_id;
  uint16_t schema_id;
  uint16_t version;
  constexpr static const char name[] = "Spectra-Simba 2.3.5. SBE Header";
};
#pragma pack(pop)

class Header : public Protocol<HeaderFormat, HeaderFormat::name> {
 private:
  size_t root_block_size_{};

  RawProto GetNextProto(const HeaderFormat& header) override {
    return header.template_id;
  };

  void Operation(const HeaderFormat& header) override;

 public:
  size_t GetRootBlockSize() const { return root_block_size_; }
};

}  // namespace packet_parse::spectra_simba::sbe
