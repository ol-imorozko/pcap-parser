#include "include/spectra_simba_data_parser.h"
#include "include/spectra_simba_sbe_parser.h"
#include "include/spectra_simba_utility.h"

namespace packet_parse::spectra_simba {

ServiceDataPtr DataParser::Parse(Stream& packet, std::streamsize& packet_size,
                                 ServiceDataPtr data) const {
  auto packet_indicator = static_cast<FormatIndicator*>(data.get());

  switch (packet_indicator->format) {
    case PacketFormat::kIncremental: {
      sbe::MessageParser mp;

      while (packet_size != 0) {
        // Simba Spectra 2.3.1. Incremental packet format
        // Packet consists of the following parts:
        // ...
        // One or more SBE messages
        //
        // So at this point we're already know that the data remaining will
        // be just one or more SBE Messages, so we can reuse the
        // basic HandleParser function that is used in main() to run
        // some SBE Message parsers.
        data = HandleParser(mp, packet, packet_size, std::move(data));
      }

      return data;
    }
    case PacketFormat::kSnapshot: {
      sbe::MessageParser mp;
      return HandleParser(mp, packet, packet_size, std::move(data));
    }
    default:
      throw UnknownProto(data->proto);
  }
}

}  // namespace packet_parse::spectra_simba
