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

void Transform(RawFileHeader& header, bool should_swap_bytes) {
  SingletonTransformer* t =
      SingletonTransformer::GetInstance(should_swap_bytes);

  header.magic_number = t->ReadU32(header.magic_number);
  header.version_major = t->ReadU16(header.version_major);
  header.version_minor = t->ReadU16(header.version_minor);
  header.snaplen = t->ReadU32(header.snaplen);
  header.linktype = t->ReadU32(header.linktype);
}

void Transform(RawPacketHeader& header, bool should_swap_bytes) {
  SingletonTransformer* t =
      SingletonTransformer::GetInstance(should_swap_bytes);

  header.ts_sec = t->ReadU32(header.ts_sec);
  header.ts_u_or_nsec = t->ReadU32(header.ts_u_or_nsec);
  header.incl_len = t->ReadU32(header.incl_len);
  header.orig_len = t->ReadU32(header.orig_len);
}

FileHeader::FileHeader(const RawFileHeader& raw_header)
    : cooked_header_(raw_header) {

  if (!FileValid(cooked_header_.magic_number))
    throw FileInvalid();

  if (cooked_header_.magic_number == kMagicMicrosecsBe ||
      cooked_header_.magic_number == kMagicNanosecsBe)
    should_swap_bytes_ = false;
  else
    should_swap_bytes_ = true;

  if (cooked_header_.magic_number == kMagicMicrosecsBe ||
      cooked_header_.magic_number == kMagicMicrosecsLe)
    tf_ = TimeFormat::kUSec;
  else
    tf_ = TimeFormat::KNSec;

  Transform(cooked_header_, should_swap_bytes_);
}

PacketHeader::PacketHeader(const RawPacketHeader& raw_header,
                           const FileHeader& file_header)
    : cooked_header_(raw_header) {

  tf_ = file_header.GetTimeFormat();

  Transform(cooked_header_, file_header.ShouldSwapBytes());
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
