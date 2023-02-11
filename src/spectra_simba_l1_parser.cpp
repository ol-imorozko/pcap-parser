#include <array>
#include <cstdint>
#include <iostream>

#include "include/spectra_simba_l1_parser.h"
#include "include/spectra_simba_utility.h"

namespace packet_parse::spectra_simba {

RawProto L1Parser::Parse(std::ifstream& file, std::streamsize& packet_size,
                         [[maybe_unused]] RawProto raw_proto) const {
  MarketDataPacket p;
  return p.Parse(file, packet_size);
}

void MarketDataPacket::Operation(const MarketDataPacketHeader& header) {
  std::cout << "Market Data Packet header:\n";
  std::cout << "  MsgSeqNum: " << header.msg_seq_num << '\n';
  std::cout << "  MsgSize: " << header.msg_size << '\n';
  std::cout << "  MsgFlags:\n";

  flags_ = std::bitset<16>(header.msg_flags);

  if (flags_[3]) {
    std::cout << "    | Incremental packet\n";

    if (flags_[0])
      std::cout << "    |   | Whole packet or the last fragment "
                   "of a packet\n";
    else
      std::cout << "    |   | Fragment of a packet\n";
  } else {
    std::cout << "    | Snapshot packet\n";

    if (flags_[1] && flags_[2])
      std::cout << "    |   | Whole packet\n";
    else if (flags_[1])
      std::cout << "    |   | First fragment of a packet\n";
    else if (flags_[2])
      std::cout << "    |   | Last fragment of a packet\n";
    else
      std::cout << "    |   | Fragment of a packet\n";
  }
  if (flags_[4])
    std::cout << "    | Broadcasting full order-books in the form of "
                 "Incremental packages\n";
  else
    std::cout << "    | Broadcasting online updates\n";

  std::cout << "  UTC time when the packet was sent by the gateway: ";
  PrintTimeStamp(header.sending_time);
}
}  // namespace packet_parse::spectra_simba
