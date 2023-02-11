#include <byteswap.h>

#include "include/transformer.h"

namespace pcap_parse {

SingletonTransformer* SingletonTransformer::singleton_ = nullptr;

SingletonTransformer* SingletonTransformer::GetInstance(
    bool should_swap_bytes) {
  if (singleton_ == nullptr) {
    singleton_ = new SingletonTransformer(should_swap_bytes);
  }
  return singleton_;
}

uint32_t SingletonTransformer::ReadU32(uint32_t data) const {
  if (should_swap_bytes_)
    return bswap_32(data);

  return data;
}

uint16_t SingletonTransformer::ReadU16(uint16_t data) const {
  if (should_swap_bytes_)
    return bswap_16(data);

  return data;
}

}  // namespace pcap_parse
