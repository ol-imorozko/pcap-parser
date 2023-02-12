#include <array>
#include <cstdint>
#include <iostream>
#include <memory>

#include "include/base_parser.h"
#include "include/spectra_simba_l1_parser.h"

namespace packet_parse::spectra_simba {

ServiceDataPtr L1Parser::Parse(Stream& packet, std::streamsize& packet_size,
                               ServiceDataPtr data) const {
  MarketDataPacket p;
#ifdef FIXME_SKIP_FRAGMENTED_PACKETS
  ServiceDataPtr next_data = p.Parse(packet, packet_size, std::move(data));
  if (p.IsFragment()) {
    std::cout << "This packet is a fragment, skip it for now\n";
    throw UnknownProto(0xDEADBEEF);
  }

  return next_data;
#else
  return p.Parse(packet, packet_size, std::move(data));
#endif
}

ServiceDataPtr MarketDataPacket::Operation(
    const MarketDataPacketHeader& header,
    [[maybe_unused]] ServiceDataPtr data) {
  PacketFormat format;

  std::cout << "Market Data Packet header:\n";
  std::cout << "  MsgSeqNum: " << header.msg_seq_num << '\n';
  std::cout << "  MsgSize: " << header.msg_size << '\n';
  std::cout << "  MsgFlags:\n";

  flags_ = std::bitset<16>(header.msg_flags);

  using namespace types;
  if (Flag(MsgFlagsSetValue::kIncrementalPacket, flags_)) {
    std::cout << "    | Incremental packet\n";
    format = PacketFormat::kIncremental;

    if (Flag(MsgFlagsSetValue::kLastFragment, flags_))
      std::cout << "    |   | Whole packet or the last fragment "
                   "of a packet\n";
    else
      std::cout << "    |   | Fragment of a packet\n";
  } else {
    std::cout << "    | Snapshot packet\n";
    format = PacketFormat::kSnapshot;

    if (Flag(MsgFlagsSetValue::kStartOfSnapshot, flags_) &&
        Flag(MsgFlagsSetValue::kEndOfSnapshot, flags_))
      std::cout << "    |   | Whole packet\n";
    else if (Flag(MsgFlagsSetValue::kStartOfSnapshot, flags_))
      std::cout << "    |   | First fragment of a packet\n";
    else if (Flag(MsgFlagsSetValue::kEndOfSnapshot, flags_))
      std::cout << "    |   | Last fragment of a packet\n";
    else
      std::cout << "    |   | Fragment of a packet\n";
  }
  if (Flag(MsgFlagsSetValue::kPossDupFlag, flags_))
    std::cout << "    | Broadcasting full order-books in the form of "
                 "Incremental packages\n";
  else
    std::cout << "    | Broadcasting online updates\n";

  std::cout << "  UTC time when the packet was sent by the gateway: ";
  PrintTimeStamp(header.sending_time);

  return std::make_unique<FormatIndicator>(format);
}
}  // namespace packet_parse::spectra_simba
