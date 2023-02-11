#pragma once

#include "include/base_parser.h"

namespace packet_parse::spectra_simba {

class DataParser : public BaseParser {
 private:
  enum class DataType {
    // As in Simba Spectra 2.3.1. Incremental packet format
    // Packet consists of the following parts:
    // ...
    // One or more SBE messages
    MultipleSBEMessages = 1,
    // As in Simba Spectra 2.3.1. Incremental packet format
    // Packet consists of the following parts:
    // ...
    // FIX message in SBE format
    //
    // Also there are RepeatingGroupDimensions header right after
    // the Root block.
    SBEMessageWithRepeating = 0,
  };

 public:
  RawProto Parse(std::ifstream& file, std::streamsize& packet_size,
                 RawProto raw_proto) const override;
};
}  // namespace packet_parse::spectra_simba
