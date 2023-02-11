#include <byteswap.h>

#include "include/transformer.h"

namespace pcap_parse {

uint32_t Transformer::ReadU32(uint32_t data) const {
  if (should_swap_bytes_)
    return bswap_32(data);

  return data;
}

uint16_t Transformer::ReadU16(uint16_t data) const {
  if (should_swap_bytes_)
    return bswap_16(data);

  return data;
}

}  // namespace pcap_parse
