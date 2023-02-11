#pragma once
#include <cstdint>

namespace pcap_parse {

class SingletonTransformer {
 private:
  bool should_swap_bytes_;
  static SingletonTransformer* singleton_;

  explicit SingletonTransformer(bool should_swap_bytes)
      : should_swap_bytes_(should_swap_bytes) {}

 public:
  SingletonTransformer(SingletonTransformer& other) = delete;

  void operator=(const SingletonTransformer&) = delete;

  static SingletonTransformer* GetInstance(bool should_swap_bytes);

  uint32_t ReadU32(uint32_t data) const;

  uint16_t ReadU16(uint16_t data) const;
};

}  // namespace pcap_parse
