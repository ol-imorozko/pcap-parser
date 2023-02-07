#pragma once
#include <cstdint>

#include "include/pcap_headers.h"

enum class Endianness {
  SAME_ENDIAN,
  DIFF_ENDIAN,
};

class PcapHeadersHelper {
 private:
  uint32_t magic_number_;
  Endianness endianness_;

  uint32_t ReadU32(uint32_t data);

  uint16_t ReadU16(uint16_t data);

 public:
  explicit PcapHeadersHelper(uint32_t magic_number);

  [[nodiscard]] bool FileValid() const;

  static void PrintPcapFileHeader(const PcapFileHeader& header);

  PcapFileHeader TransfrormRawFileHeader(PcapFileHeader& header);

  static void PrintPcapPacketHeader(const PcapPacketHeader& header);

  PcapPacketHeader TransfrormRawPacketHeader(PcapPacketHeader& header);
};
