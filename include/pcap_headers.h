#pragma once
#include <algorithm>
#include <cstdint>

#include "include/raw_pcap_headers.h"
#include "include/transformer.h"

namespace pcap_parse {

class FileHeader {
 private:
  RawFileHeader cooked_header_;
  bool should_swap_bytes_;
  TimeFormat tf_;

 public:
  explicit FileHeader(const RawFileHeader& raw_header);

  [[nodiscard]] bool ShouldSwapBytes() const { return should_swap_bytes_; }

  [[nodiscard]] TimeFormat GetTimeFormat() const { return tf_; }

  [[nodiscard]] uint32_t GetLinkType() const { return cooked_header_.linktype; }

  void Print() const;
};

class PacketHeader {
 private:
  RawPacketHeader cooked_header_;
  TimeFormat tf_;
  void PrintTimeStamp() const;

 public:
  explicit PacketHeader(const RawPacketHeader& raw_header,
                        const FileHeader& file_header);

  [[nodiscard]] size_t GetRealPacketLength() const {
    return std::min(cooked_header_.incl_len, cooked_header_.orig_len);
  }

  [[nodiscard]] size_t GetCapturedPacketLength() const {
    return cooked_header_.incl_len;
  }

  void Print() const;
};

}  // namespace pcap_parse
