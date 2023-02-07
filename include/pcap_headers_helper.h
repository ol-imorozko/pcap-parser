#pragma once
#include <cstdint>

#include "include/pcap_headers.h"

enum class Endianness {
  SAME_ENDIAN,
  DIFF_ENDIAN,
};

class PcapHeadersHelper {
private:
  uint32_t magic_number{};
  Endianness endianness;

  uint32_t read_u32(uint32_t data);

  uint16_t read_u16(uint16_t data);

public:
  explicit PcapHeadersHelper(uint32_t magic_number);

  [[nodiscard]] bool file_valid() const;

  static void printPcapFileHeader(const PcapFileHeader &header);

  PcapFileHeader transfrormRawFileHeader(PcapFileHeader &header);

  static void printPcapPacketHeader(const PcapPacketHeader &header);

  PcapPacketHeader transfrormRawPacketHeader(PcapPacketHeader &header);
};
