#pragma once

#include "include/base_parser.h"
#include "include/spectra_simba_types.h"

namespace packet_parse::spectra_simba {

class L2Parser : public BaseParser {
 public:
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) const override;
};

#pragma pack(push, 1)
struct IncrementalHeader {
  uint64_t transact_time;
  types::ExchangeTradingSessionID exchange_trading_session_id;
  constexpr static const char name[] =
      "Spectra-Simba 2.3.1. Incremental packet format";
};
#pragma pack(pop)

class Incremental
    : public Protocol<IncrementalHeader, IncrementalHeader::name> {
 private:
  ServiceDataPtr Operation(const IncrementalHeader& header,
                           ServiceDataPtr data) override;
};

}  // namespace packet_parse::spectra_simba
