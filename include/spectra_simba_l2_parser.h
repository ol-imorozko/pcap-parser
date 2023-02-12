#pragma once

#include "include/base_parser.h"

namespace packet_parse::spectra_simba {

class L2Parser : public BaseParser {
 private:
  enum class PacketType {
    Incremental = 1,
    Snapshot = 0,
  };

 public:
  RawProto Parse(Stream& packet, std::streamsize& packet_size,
                 RawProto raw_proto) override;
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
  constexpr static const uint32_t id_null_value = 4294967295;
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

  RawProto GetNextProto(
      [[maybe_unused]] const IncrementalHeader& header) override {
    // If the packet is Incremental, we know that the next data will
    // be multiple SBE messages. Let's mark that case with "1".
    //
    // With snapshot header, the next data will be one SBE message with
    // the repeating group dimensions after the Root block. We will
    // mark that case with "0"
    return 1;
  }

  void Operation(const IncrementalHeader& header) override;
};

}  // namespace packet_parse::spectra_simba
