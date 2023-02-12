#pragma once

#include "include/base_parser.h"

namespace packet_parse::spectra_simba {

class L2Parser : public BaseParser {
 public:
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) const override;
};

#pragma pack(push, 1)
struct IncrementalHeader {
  uint64_t transact_time;
  uint32_t exchange_trading_session_id;
  constexpr static const char name[] =
      "Spectra-Simba 2.3.1. Incremental packet format";

  // This is the null value for the optional <type name="ExchangeTradingSessionID">
  // in a <composite name="IncrementalPacketHeader"> as per
  // Spectra-Simba message schema ver. FIX5SP2
  constexpr static uint32_t id_null_value = 4294967295;
};
#pragma pack(pop)

class Incremental
    : public Protocol<IncrementalHeader, IncrementalHeader::name> {
 private:
  static bool exchange_trading_session_id_present(
      const IncrementalHeader& header) {
    return header.exchange_trading_session_id !=
           IncrementalHeader::id_null_value;
  }

  ServiceDataPtr Operation(const IncrementalHeader& header,
                           ServiceDataPtr data) override;
};

}  // namespace packet_parse::spectra_simba
