#pragma once
#include <byteswap.h>
#include <cstdint>

enum class Endianness {
  SAME_ENDIAN,
  DIFF_ENDIAN,
};

class Transformer {
 private:
  Endianness endianness_;

 public:
  explicit Transformer(Endianness endianness) : endianness_(endianness) {}

  uint32_t ReadU32(uint32_t data) {
    if (endianness_ == Endianness::SAME_ENDIAN)
      return data;

    return bswap_32(data);
  }

  uint16_t ReadU16(uint16_t data) {
    if (endianness_ == Endianness::SAME_ENDIAN)
      return data;

    return bswap_16(data);
  }
};