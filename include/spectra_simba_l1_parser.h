#pragma once
#include <arpa/inet.h>
#include <bit>
#include <bitset>
#include <utility>

#include "include/base_parser.h"

#define FIXME_SKIP_FRAGMENTED_PACKETS 1

namespace packet_parse::spectra_simba {

class L1Parser : public BaseParser {
 public:
  RawProto Parse(Stream& packet, std::streamsize& packet_size,
                 RawProto raw_proto) override;
};

#pragma pack(push, 1)
struct MarketDataPacketHeader {
  uint32_t msg_seq_num;
  uint16_t msg_size;
  uint16_t msg_flags;
  uint64_t sending_time;
  constexpr static const char name[] =
      "Spectra-Simba 2.3.3: Market Data Packet Header";
};
#pragma pack(pop)

class MarketDataPacket
    : public Protocol<MarketDataPacketHeader, MarketDataPacketHeader::name> {
 private:
  std::bitset<16> flags_;

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

  RawProto GetNextProto(const MarketDataPacketHeader& header) override {
    // 0 - flag of the 'Snapshot' packet, 1 - flag of the 'Incremental' packet
    return static_cast<RawProto>((header.msg_flags & 0x8) ? 1 : 0);
  }

  void Operation(const MarketDataPacketHeader& header) override;

#ifdef FIXME_SKIP_FRAGMENTED_PACKETS
 public:
  bool IsFragment() {
    return ((flags_[3] && !flags_[0]) ||
            (!flags_[3] && !(flags_[1] && flags_[2])));
  }
#endif
};

}  // namespace packet_parse::spectra_simba
