#include <chrono>
#include <cstdint>
#include <iomanip>
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
  std::cout << "Magic Number: 0x" << std::hex << magic_number << std::dec
            << '\n';
  std::cout << "Version Major: " << version_major << '\n';
  std::cout << "Version Minor: " << version_minor << '\n';
  std::cout << "Snaplen: " << snaplen << '\n';
  std::cout << "Linktype: " << linktype << '\n';
  std::cout << "*****************" << std::endl;
}

void PcapPacketHeader::Transform(Transformer& t) {
  ts_sec = t.ReadU32(ts_sec);
  ts_u_or_nsec = t.ReadU32(ts_u_or_nsec);
  incl_len = t.ReadU32(incl_len);
  orig_len = t.ReadU32(orig_len);
}

void PcapPacketHeader::Print() const {
  std::cout << "Pcap Packet Header\n";
  std::cout << "-----------------\n";
  std::cout << "Timestamp Seconds: " << ts_sec << '\n';
  std::cout << "Timestamp micro/nanoseconds: " << ts_u_or_nsec << '\n';
  std::cout << "Number of octets: " << incl_len << '\n';
  std::cout << "Actual length: " << orig_len << '\n';
  std::cout << "-----------------" << std::endl;
}

void PcapPacketHeader::PrintTimeStamp(TimeFormat& tf) const {
  using namespace std::chrono;

  auto timePoint = system_clock::from_time_t(ts_sec);

  if (tf == TimeFormat::KNSec)
    timePoint += nanoseconds(ts_u_or_nsec);
  else
    timePoint += microseconds(ts_u_or_nsec);

  auto t = system_clock::to_time_t(timePoint);
  std::tm tm = *std::localtime(&t);

  std::cout << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");

  if (tf == TimeFormat::KNSec) {
    auto ns = duration_cast<nanoseconds>(timePoint.time_since_epoch());
    auto fraction = ns.count() % 1000000000;

    std::cout << "." << std::setfill('0') << std::setw(9) << fraction
              << std::endl;
  } else {
    std::cout << "." << std::setfill('0') << std::setw(6) << ts_u_or_nsec
              << std::endl;
  }
}
