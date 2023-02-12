#pragma once
#include <cstdint>

namespace packet_parse::spectra_simba::types {
struct Decimal5 {
  int64_t mantissa;
  constexpr static const int8_t exponent = -5;
};
}  // namespace packet_parse::spectra_simba::types
