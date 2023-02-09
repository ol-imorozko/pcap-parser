#pragma once
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <utility>

namespace packet_parse {

// Different protocols could use different fixed num unsigned
// data types, so in order to create a unified interface it
// is better to cast such types to uint64_t.
using RawProto = uint64_t;

// All parsers should implement such function.
//
// @p file -- Stream with the data. Parsers could read from it, but
// SHOULD NOT read more than the size of a corresponding protocol header.
// It is guaranteed that the first bytes in a @file are gonna be a bytes
// of the header.
//
// @p packet_size -- Size of a whole packet. Parsers should decrease
// this value when they finish the parsing.
//
// @p proto -- Raw protocol. It is advized to cast this to the
// internal enum with the protocols for the particullar layer.
class BaseParser {
 public:
  virtual RawProto Parse(std::ifstream& file, size_t& packet_size,
                         RawProto raw_proto) = 0;
};

void HexdumpBytes(std::ifstream& file, size_t size);

void TrimBytes(std::ifstream& file, size_t size);

RawProto HandleParser(BaseParser& p, std::ifstream& file, size_t& packet_size,
                      RawProto curr_proto);

class UnknownProto : public std::exception {
 private:
  std::string msg;

 public:
  explicit UnknownProto(RawProto proto);

  const char* what() const noexcept override { return msg.c_str(); };
};

class NotEnoughData : public std::exception {
 private:
  std::string msg;

 public:
  NotEnoughData(const std::string& protocol_name, size_t protocol_header_size,
                size_t obtained_size);

  const char* what() const noexcept override { return msg.c_str(); };
};

class EoF : public std::exception {
 private:
  std::string msg;

 public:
  EoF(const std::string& protocol_name, size_t protocol_header_size,
      size_t obtained_size);

  const char* what() const noexcept override { return msg.c_str(); };
};

}  // namespace packet_parse
