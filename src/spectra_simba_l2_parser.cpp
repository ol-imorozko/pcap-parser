#include <array>
#include <cstdint>
#include <iostream>

#include "include/spectra_simba_l2_parser.h"
#include "include/spectra_simba_utility.h"

namespace packet_parse::spectra_simba {

RawProto L2Parser::Parse(Stream& packet, std::streamsize& packet_size,
                         [[maybe_unused]] RawProto raw_proto) {
  auto proto = static_cast<PacketType>(raw_proto);

  switch (proto) {
    case PacketType::Incremental: {
      Incremental p;
      return p.Parse(packet, packet_size);
    }
    case PacketType::Snapshot:
      // Next protocol identifier is zero if the packet is Snapshot
      //
      // See "include/spectra_simba_l2_parser.h : Incremental::GetNextProto"
      // for details
      return 0;
    default:
      throw UnknownProto(raw_proto);
  }
}

void Incremental::Operation(const IncrementalHeader& header) {
  std::cout << "Incremental Packet Header:\n";
  std::cout
      << "  UTC time of the beginning of transaction processing in matching: ";
  PrintTimeStamp(header.transact_time);
  std::cout << "  Trading session identifier: ";
  if (exchange_trading_session_id_present(header))
    std::cout << header.exchange_trading_session_id << '\n';
  else
    std::cout << "Not present\n";
}

}  // namespace packet_parse::spectra_simba
