#pragma once
#include <cstdint>

#include "include/raw_pcap_headers.h"
#include "include/transformer.h"

namespace pcap_parse {

class FileHeader {
 private:
  RawFileHeader& cooked_header_;
  Endianness endianness_;
  TimeFormat tf_;
  LinkType lt_;

 public:
  explicit FileHeader(RawFileHeader& raw_header);

  [[nodiscard]] Endianness GetEndianness() const { return endianness_; }

  [[nodiscard]] TimeFormat GetTimeFormat() const { return tf_; }

  [[nodiscard]] LinkType GetLinkType() const { return lt_; }

  void Print() const;
};

class PacketHeader {
 private:
  RawPacketHeader& cooked_header_;
  TimeFormat tf_;

 public:
  explicit PacketHeader(RawPacketHeader& raw_header, FileHeader& file_header);

  [[nodiscard]] unsigned int GetCapturedPacketLength() const {
    return cooked_header_.incl_len;
  }

  void Print() const;
  void PrintTimeStamp() const;
};

}  // namespace pcap_parse
