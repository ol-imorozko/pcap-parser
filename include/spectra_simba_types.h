#pragma once
#include <bitset>
#include <cstdint>

// These are the types from Spectra Simba schema ver. FIX5SP2
namespace packet_parse::spectra_simba::types {
struct Decimal5 {
  int64_t mantissa;
  constexpr static const int8_t exponent = -5;
};

enum class MsgFlagsSetValue {
  kLastFragment = 0,
  kStartOfSnapshot = 1,
  kEndOfSnapshot = 2,
  kIncrementalPacket = 3,
  kPossDupFlag = 4,
};

template <typename Enum, size_t N>
bool Flag(Enum value, std::bitset<N> bitset) {
  return bitset[static_cast<size_t>(value)];
}

using MsgFlagsSet = uint16_t;

}  // namespace packet_parse::spectra_simba::types
