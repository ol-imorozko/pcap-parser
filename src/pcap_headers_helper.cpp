#include <byteswap.h>
#include <iostream>

#include "include/pcap_headers_helper.h"

uint32_t PcapHeadersHelper::read_u32(uint32_t data) {
  if (endianness == Endianness::SAME_ENDIAN)
    return data;

  return bswap_32(data);
}

uint16_t PcapHeadersHelper::read_u16(uint16_t data) {
  if (endianness == Endianness::SAME_ENDIAN)
    return data;

  return bswap_16(data);
}

PcapHeadersHelper::PcapHeadersHelper(uint32_t magic_number)
    : magic_number(magic_number) {
  if (magic_number == MAGIC_MICROSECS_BE || magic_number == MAGIC_NANOSECS_BE)
    endianness = Endianness::SAME_ENDIAN;
  else
    endianness = Endianness::DIFF_ENDIAN;
}

[[nodiscard]] bool PcapHeadersHelper::file_valid() const {
  return magic_number == MAGIC_MICROSECS_BE ||
         magic_number == MAGIC_MICROSECS_LE ||
         magic_number == MAGIC_NANOSECS_BE || magic_number == MAGIC_NANOSECS_LE;
}

PcapFileHeader
PcapHeadersHelper::transfrormRawFileHeader(PcapFileHeader &header) {
  header.magic_number = read_u32(header.magic_number);
  header.version_major = read_u16(header.version_major);
  header.version_minor = read_u16(header.version_minor);
  header.snaplen = read_u32(header.snaplen);
  header.linktype = read_u32(header.linktype);

  return header;
}

PcapPacketHeader
PcapHeadersHelper::transfrormRawPacketHeader(PcapPacketHeader &header) {
  header.ts_sec = read_u32(header.ts_sec);
  header.ts_usec = read_u16(header.ts_usec);
  header.incl_len = read_u16(header.incl_len);
  header.orig_len = read_u32(header.orig_len);

  return header;
}

void PcapHeadersHelper::printPcapPacketHeader(const PcapPacketHeader &header) {
  std::cout << "Pcap Packet Header" << std::endl;
  std::cout << "-----------------" << std::endl;
  std::cout << "Timestamp Seconds: " << header.ts_sec << std::endl;
  std::cout << "Timestamp micro/nanoseconds: " << header.ts_usec << std::endl;
  std::cout << "Number of octets: " << header.incl_len << std::endl;
  std::cout << "Actual length: " << header.orig_len << std::endl;
  std::cout << "-----------------" << std::endl;
}

void PcapHeadersHelper::printPcapFileHeader(const PcapFileHeader &header) {
  std::cout << "Pcap File Header" << std::endl;
  std::cout << "*****************" << std::endl;
  std::cout << "Magic Number: 0x" << std::hex << header.magic_number
            << std::endl;
  std::cout << "Version Major: " << header.version_major << std::endl;
  std::cout << "Version Minor: " << header.version_minor << std::endl;
  std::cout << "Snaplen: " << header.snaplen << std::endl;
  std::cout << "Linktype: " << header.linktype << std::endl;
  std::cout << "*****************" << std::endl;
}
