#pragma once
#include <cstdint>
#include <functional>
#include <string>

#include "include/raw_pcap_headers.h"
#include "include/transformer.h"

class PcapFileHeader {
 private:
  RawPcapFileHeader& cooked_header_;
  Endianness endianness_;
  TimeFormat tf_;
  LinkType lt_;

 public:
  explicit PcapFileHeader(RawPcapFileHeader& raw_header);

  [[nodiscard]] Endianness GetEndianness() const { return endianness_; }

  [[nodiscard]] TimeFormat GetTimeFormat() const { return tf_; }

  [[nodiscard]] LinkType GetLinkType() const { return lt_; }

  void Print() const;
};

class PcapPacketHeader {
 private:
  RawPcapPacketHeader& cooked_header_;
  TimeFormat tf_;

 public:
  explicit PcapPacketHeader(RawPcapPacketHeader& raw_header,
                            PcapFileHeader& file_header);

  [[nodiscard]] unsigned int GetCapturedPacketLength() const {
    return cooked_header_.incl_len;
  }

  void Print() const;
  void PrintTimeStamp() const;
};
