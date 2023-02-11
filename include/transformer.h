#pragma once
#include <cstdint>

namespace pcap_parse {

class Transformer {
 private:
  bool should_swap_bytes_{};

 public:
  explicit Transformer(bool should_swap_bytes)
      : should_swap_bytes_(should_swap_bytes) {}

  Transformer() = default;

  uint32_t ReadU32(uint32_t data) const;

  uint16_t ReadU16(uint16_t data) const;
};

}  // namespace pcap_parse
