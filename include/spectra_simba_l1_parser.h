#pragma once
#include <arpa/inet.h>
#include <bit>
#include <bitset>
#include <cstdint>
#include <utility>

#include "include/base_parser.h"
#include "include/spectra_simba_types.h"
#include "include/spectra_simba_utility.h"

#define FIXME_SKIP_FRAGMENTED_PACKETS 1

namespace packet_parse::spectra_simba {

class L1Parser : public BaseParser {
 public:
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) const override;
};

#pragma pack(push, 1)
struct MarketDataPacketHeader {
  uint32_t msg_seq_num;
  uint16_t msg_size;
  types::MsgFlagsSet msg_flags;
  uint64_t sending_time;
  constexpr static const char name[] =
      "Spectra-Simba 2.3.3: Market Data Packet Header";
};
#pragma pack(pop)

class MarketDataPacket
    : public Protocol<MarketDataPacketHeader, MarketDataPacketHeader::name> {
 private:
#ifdef FIXME_SKIP_FRAGMENTED_PACKETS
  std::bitset<16> flags_;
#endif

  void Transform([[maybe_unused]] MarketDataPacketHeader& header) override {
    // From Spectra Simba 2.3.3. Market Data Packet Header:
    // Byte order of encoding is little-endian.
    //
    // Let's assume that we're working on a little-endian system simply
    // because there is no point in writing big-endian compatible code
    // for such market excange protocol. It will be significantly slower
    // due to the swapping of the bytes.
    static_assert(std::endian::native == std::endian::little);
  }

  ServiceDataPtr Operation(const MarketDataPacketHeader& header,
                           ServiceDataPtr data) override;

#ifdef FIXME_SKIP_FRAGMENTED_PACKETS
 public:
  bool IsFragment() {
    return ((flags_[3] && !flags_[0]) ||
            (!flags_[3] && !(flags_[1] && flags_[2])));
  }
#endif
};

}  // namespace packet_parse::spectra_simba
