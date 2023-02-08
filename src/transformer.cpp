#include <byteswap.h>

#include "include/transformer.h"

namespace pcap_parse {

SingletonTransformer* SingletonTransformer::singleton_ = nullptr;

SingletonTransformer* SingletonTransformer::GetInstance(Endianness endianness) {
  if (singleton_ == nullptr) {
    singleton_ = new SingletonTransformer(endianness);
  }
  return singleton_;
}

uint32_t SingletonTransformer::ReadU32(uint32_t data) {
  if (endianness_ == Endianness::kSameEndian)
    return data;

  return bswap_32(data);
}

uint16_t SingletonTransformer::ReadU16(uint16_t data) {
  if (endianness_ == Endianness::kSameEndian)
    return data;

  return bswap_16(data);
}

}  // namespace pcap_parse
