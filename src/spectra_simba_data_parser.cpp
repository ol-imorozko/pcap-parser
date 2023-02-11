#include "include/spectra_simba_data_parser.h"
#include "include/spectra_simba_sbe_parser.h"

namespace packet_parse::spectra_simba {

RawProto DataParser::Parse(std::ifstream& file, std::streamsize& packet_size,
                           RawProto raw_proto) const {
  auto proto = static_cast<DataType>(raw_proto);

  switch (proto) {
    case DataType::MultipleSBEMessages: {
      sbe::MessageParser p;

      while (packet_size != 0) {
        // At this point we're already know that the data remaining will
        // be just one or more SBE Messages, so we can reuse the
        // basic HandleParser function that is used in main() to run
        // some SBE Message parsers.
        // Also we don't care about the "next_proto" argument, hence
        // zero as a last argument.
        HandleParser(p, file, packet_size, 0);
      }

      return 0;
    }
    case DataType::SBEMessageWithRepeating: {
      sbe::MessageParser mp;
      HandleParser(mp, file, packet_size, 0);

      /* RepeatingSectionParser rsp; */
      /* HandleParser(rsp, file, packet_size, 0); */

      return 0;
    }
    default:
      throw UnknownProto(raw_proto);
  }
}

}  // namespace packet_parse::spectra_simba
