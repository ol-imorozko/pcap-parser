#pragma once
#include <ios>

namespace packet_parse {

// Different protocols could use different fixed num unsigned
// data types, so in order to create a unified interface it
// is better to cast such types to uint64_t.
using RawProto = uint64_t;

class BaseParser {
 public:
  // All parsers should implement such function.
  //
  // @p file -- Stream with the data. Parsers could read from it, but
  // MUST NOT read more than the size of a corresponding protocol header.
  //
  // @p packet_size -- Size of a whole packet. Parsers should decrease
  // this value when they finish the parsing.
  //
  // @p proto -- Raw protocol. It is advized to cast this to the
  // internal enum with the protocols for the particular layer.
  virtual RawProto Parse(std::ifstream& file, std::streamsize& packet_size,
                         RawProto raw_proto) = 0;
};

void HexdumpBytes(std::ifstream& file, std::streamsize n);

void TrimBytes(std::ifstream& file, std::streamsize n);

RawProto HandleParser(BaseParser& p, std::ifstream& file,
                      std::streamsize& packet_size, RawProto curr_proto);

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
