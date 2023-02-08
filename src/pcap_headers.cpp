#include <cstdint>
#include <iostream>

#include "include/pcap_headers.h"

void PcapFileHeader::Transform(Transformer& t) {
  magic_number = t.ReadU32(magic_number);
  version_major = t.ReadU16(version_major);
  version_minor = t.ReadU16(version_minor);
  snaplen = t.ReadU32(snaplen);
  linktype = t.ReadU32(linktype);
}

void PcapFileHeader::Print() const {
  std::cout << "Pcap File Header\n";
  std::cout << "*****************\n";
  std::cout << "Magic Number: 0x" << std::hex << magic_number << '\n';
  std::cout << "Version Major: " << version_major << '\n';
  std::cout << "Version Minor: " << version_minor << '\n';
  std::cout << "Snaplen: " << snaplen << '\n';
  std::cout << "Linktype: " << linktype << '\n';
  std::cout << "*****************" << std::endl;
}

void PcapPacketHeader::Transform(Transformer& t) {
  ts_sec = t.ReadU32(ts_sec);
  ts_usec = t.ReadU32(ts_usec);
  incl_len = t.ReadU32(incl_len);
  orig_len = t.ReadU32(orig_len);
}

void PcapPacketHeader::Print() const {
  std::cout << "Pcap Packet Header\n";
  std::cout << "-----------------\n";
  std::cout << "Timestamp Seconds: " << ts_sec << '\n';
  std::cout << "Timestamp micro/nanoseconds: " << ts_usec << '\n';
  std::cout << "Number of octets: " << incl_len << '\n';
  std::cout << "Actual length: " << orig_len << '\n';
  std::cout << "-----------------" << std::endl;
}
