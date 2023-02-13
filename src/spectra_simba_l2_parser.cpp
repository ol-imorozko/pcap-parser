#include <array>
#include <cstdint>
#include <iostream>

#include "include/spectra_simba_l2_parser.h"
#include "include/spectra_simba_utility.h"

namespace packet_parse::spectra_simba {

ServiceDataPtr L2Parser::Parse(Stream& packet, std::streamsize& packet_size,
                               ServiceDataPtr data) const {

  auto packet_indicator = static_cast<FormatIndicator*>(data.get());

  switch (packet_indicator->format) {
    case PacketFormat::kIncremental: {
      Incremental p;
      return p.Parse(packet, packet_size, std::move(data));
    }
    case PacketFormat::kSnapshot:
      return data;
    default:
      throw UnknownProto(data->proto);
  }
}

ServiceDataPtr Incremental::Operation(const IncrementalHeader& header,
                                      ServiceDataPtr data) {
  std::cout << "Incremental Packet Header:\n";
  std::cout
      << "  UTC time of the beginning of transaction processing in matching: ";
  PrintTimeStamp(header.transact_time);
  std::cout << "  Trading session identifier: "
            << header.exchange_trading_session_id << '\n';

  return data;
}

}  // namespace packet_parse::spectra_simba
