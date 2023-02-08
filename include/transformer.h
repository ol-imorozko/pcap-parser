#pragma once
#include <cstdint>

namespace pcap_parse {

enum class Endianness {
  kSameEndian,
  kDiffEndian,
};

class SingletonTransformer {
 private:
  Endianness endianness_;
  static SingletonTransformer* singleton_;

  explicit SingletonTransformer(Endianness endianness)
      : endianness_(endianness) {}

 public:
  SingletonTransformer(SingletonTransformer& other) = delete;

  void operator=(const SingletonTransformer&) = delete;

  static SingletonTransformer* GetInstance(Endianness endianness);

  uint32_t ReadU32(uint32_t data);

  uint16_t ReadU16(uint16_t data);
};

}  // namespace pcap_parse
