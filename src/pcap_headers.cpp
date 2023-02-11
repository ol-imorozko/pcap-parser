#include <chrono>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>

#include "include/pcap_headers.h"

namespace pcap_parse {

bool FileValid(uint32_t magic_number) {
  return magic_number == kMagicMicrosecsBe ||
         magic_number == kMagicMicrosecsLe ||
         magic_number == kMagicNanosecsBe || magic_number == kMagicNanosecsLe;
}

class FileInvalid : public std::exception {
 public:
  const char* what() const noexcept override {
    return "Provided file is not a PCAP file";
  };
};

void Transform(RawFileHeader& raw_header, bool should_swap_bytes) {
  SingletonTransformer* t =
      SingletonTransformer::GetInstance(should_swap_bytes);

  raw_header.magic_number = t->ReadU32(raw_header.magic_number);
  raw_header.version_major = t->ReadU16(raw_header.version_major);
  raw_header.version_minor = t->ReadU16(raw_header.version_minor);
  raw_header.snaplen = t->ReadU32(raw_header.snaplen);
  raw_header.linktype = t->ReadU32(raw_header.linktype);
}

void Transform(RawPacketHeader& raw_header, bool should_swap_bytes) {
  SingletonTransformer* t =
      SingletonTransformer::GetInstance(should_swap_bytes);

  raw_header.ts_sec = t->ReadU32(raw_header.ts_sec);
  raw_header.ts_u_or_nsec = t->ReadU32(raw_header.ts_u_or_nsec);
  raw_header.incl_len = t->ReadU32(raw_header.incl_len);
  raw_header.orig_len = t->ReadU32(raw_header.orig_len);
}

FileHeader::FileHeader(RawFileHeader& raw_header) : cooked_header_(raw_header) {

  if (!FileValid(raw_header.magic_number))
    throw FileInvalid();

  if (raw_header.magic_number == kMagicMicrosecsBe ||
      raw_header.magic_number == kMagicNanosecsBe)
    should_swap_bytes_ = false;
  else
    should_swap_bytes_ = true;

  if (raw_header.magic_number == kMagicMicrosecsBe ||
      raw_header.magic_number == kMagicMicrosecsLe)
    tf_ = TimeFormat::kUSec;
  else
    tf_ = TimeFormat::KNSec;

  //Now our private header (cooked_header_) has correct fields
  Transform(raw_header, should_swap_bytes_);
}

PacketHeader::PacketHeader(RawPacketHeader& raw_header, FileHeader& file_header)
    : cooked_header_(raw_header) {

  tf_ = file_header.GetTimeFormat();

  //Now our private header (cooked_header_) has correct fields
  Transform(raw_header, file_header.ShouldSwapBytes());
}

std::string TimeFormatToString(TimeFormat tf) {
  return tf == TimeFormat::kUSec ? "microseconds" : "nanoseconds";
}

void FileHeader::Print() const {
  std::cout << "Pcap File Header\n";
  std::cout << "*****************\n";
  std::cout << "Magic Number: 0x" << std::hex << cooked_header_.magic_number
            << std::dec << '\n';
  std::cout << "Version Major: " << cooked_header_.version_major << '\n';
  std::cout << "Version Minor: " << cooked_header_.version_minor << '\n';
  std::cout << "Snaplen: " << cooked_header_.snaplen << '\n';
  std::cout << "Linktype: " << cooked_header_.linktype << '\n';
  std::cout << "Using " << TimeFormatToString(tf_) << " timestamps\n";
  std::cout << "*****************\n";
}

void PacketHeader::PrintTimeStamp() const {
  using namespace std::chrono;

  auto timePoint = system_clock::from_time_t(cooked_header_.ts_sec);

  if (tf_ == TimeFormat::KNSec)
    timePoint += nanoseconds(cooked_header_.ts_u_or_nsec);
  else
    timePoint += microseconds(cooked_header_.ts_u_or_nsec);

  auto t = system_clock::to_time_t(timePoint);
  std::tm tm = *std::localtime(&t);

  std::cout << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");

  if (tf_ == TimeFormat::KNSec) {
    auto ns = duration_cast<nanoseconds>(timePoint.time_since_epoch());
    auto fraction = ns.count() % 1000000000;

    std::cout << "." << std::setfill('0') << std::setw(9) << fraction << '\n';
  } else {
    std::cout << "." << std::setfill('0') << std::setw(6)
              << cooked_header_.ts_u_or_nsec << '\n';
  }
}

void PacketHeader::Print() const {
  std::cout << "Pcap Packet Header\n";
  std::cout << "-----------------\n";
  std::cout << "Timestamp Seconds: " << cooked_header_.ts_sec << '\n';
  std::cout << "Timestamp micro/nanoseconds: " << cooked_header_.ts_u_or_nsec
            << '\n';
  std::cout << "Number of octets: " << cooked_header_.incl_len << '\n';
  std::cout << "Actual length: " << cooked_header_.orig_len << '\n';
  std::cout << "Human-readable time is ";
  PrintTimeStamp();
  std::cout << "-----------------\n";
}

}  // namespace pcap_parse
