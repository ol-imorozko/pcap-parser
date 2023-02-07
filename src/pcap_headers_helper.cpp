#include <byteswap.h>
#include <iostream>

#include "include/pcap_headers_helper.h"

uint32_t PcapHeadersHelper::ReadU32(uint32_t data) {
  if (endianness_ == Endianness::SAME_ENDIAN)
    return data;

  return bswap_32(data);
}

uint16_t PcapHeadersHelper::ReadU16(uint16_t data) {
  if (endianness_ == Endianness::SAME_ENDIAN)
    return data;

  return bswap_16(data);
}

PcapHeadersHelper::PcapHeadersHelper(uint32_t magic_number)
    : magic_number_(magic_number) {
  if (magic_number == kMagicMicrosecsBe || magic_number == kMagicNanosecsBe)
    endianness_ = Endianness::SAME_ENDIAN;
  else
    endianness_ = Endianness::DIFF_ENDIAN;
}

[[nodiscard]] bool PcapHeadersHelper::FileValid() const {
  return magic_number_ == kMagicMicrosecsBe ||
         magic_number_ == kMagicMicrosecsLe ||
         magic_number_ == kMagicNanosecsBe || magic_number_ == kMagicnanosecsLe;
}

PcapFileHeader PcapHeadersHelper::TransfrormRawFileHeader(
    PcapFileHeader& header) {
  header.magic_number = ReadU32(header.magic_number);
  header.version_major = ReadU16(header.version_major);
  header.version_minor = ReadU16(header.version_minor);
  header.snaplen = ReadU32(header.snaplen);
  header.linktype = ReadU32(header.linktype);

  return header;
}

PcapPacketHeader PcapHeadersHelper::TransfrormRawPacketHeader(
    PcapPacketHeader& header) {
  header.ts_sec = ReadU32(header.ts_sec);
  header.ts_usec = ReadU32(header.ts_usec);
  header.incl_len = ReadU32(header.incl_len);
  header.orig_len = ReadU32(header.orig_len);

  return header;
}

void PcapHeadersHelper::PrintPcapPacketHeader(const PcapPacketHeader& header) {
  std::cout << "Pcap Packet Header\n";
  std::cout << "-----------------\n";
  std::cout << "Timestamp Seconds: " << header.ts_sec << '\n';
  std::cout << "Timestamp micro/nanoseconds: " << header.ts_usec << '\n';
  std::cout << "Number of octets: " << header.incl_len << '\n';
  std::cout << "Actual length: " << header.orig_len << '\n';
  std::cout << "-----------------" << std::endl;
}

void PcapHeadersHelper::PrintPcapFileHeader(const PcapFileHeader& header) {
  std::cout << "Pcap File Header\n";
  std::cout << "*****************\n";
  std::cout << "Magic Number: 0x" << std::hex << header.magic_number << '\n';
  std::cout << "Version Major: " << header.version_major << '\n';
  std::cout << "Version Minor: " << header.version_minor << '\n';
  std::cout << "Snaplen: " << header.snaplen << '\n';
  std::cout << "Linktype: " << header.linktype << '\n';
  std::cout << "*****************" << std::endl;
}
