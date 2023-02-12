#pragma once

#include "include/base_parser.h"
#include "include/spectra_simba_types.h"

namespace packet_parse::spectra_simba::sbe {

class MessageParser : public BaseParser {
 public:
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) const override;
};

class HeaderParser : public BaseParser {
 public:
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) const override;
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
  RawProto GetNextProto(const HeaderFormat& header) override {
    return header.template_id;
  };

  ServiceDataPtr Operation(const HeaderFormat& header,
                           ServiceDataPtr data) override;
};

class RootBlockParser : public BaseParser {
 private:
  enum class MessageType {
    kLogon = 1000,
    kLogout = 1001,
    kHeartbeat = 1,
    kSequenceReset = 2,
    kBestPrices = 3,
    kEmptyBook = 4,
    kOrderUpdate = 5,
    kOrderExecution = 6,
    kOrderBookSnapshot = 7,
    kSecurityDefinition = 12,
    kSecurityStatus = 9,
    kSecurityDefinitionUpdateReport = 10,
    kTradingSessionStatus = 11,
    kMarketDataRequest = 1002,
    kDiscreteAuction = 13
  };

  static std::string MessageTypeToString(MessageType t);

 public:
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) const override;
};

}  // namespace packet_parse::spectra_simba::sbe
