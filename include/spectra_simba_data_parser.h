#pragma once

#include "include/base_parser.h"

namespace packet_parse::spectra_simba {

class DataParser : public BaseParser {
 public:
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) const override;
};
}  // namespace packet_parse::spectra_simba
