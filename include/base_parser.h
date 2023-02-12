#pragma once
#include <exception>
#include <fstream>
#include <ios>
#include <utility>

namespace packet_parse {

using Stream = std::basic_istream<char>;

// Different protocols could use different fixed num unsigned
// data types, so in order to create a unified interface it
// is better to cast such types to uint64_t.
using RawProto = uint64_t;

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

class BaseParser {
 public:
  virtual RawProto Parse(Stream& packet, std::streamsize& packet_size,
                         RawProto raw_proto) = 0;
};

// Parametrized by a packed structure with protocol header definition and
// the protocol name
template <class Header, char const* name>
class Protocol {
 private:
  std::streamsize header_size_;
  std::string name_;

  Header GetHeader(Stream& packet, std::streamsize& packet_size);

  virtual void Transform([[maybe_unused]] Header& header){};

  virtual RawProto GetNextProto([[maybe_unused]] const Header& header) {
    return 0;
  };

  virtual void Operation([[maybe_unused]] const Header& header){};

 public:
  Protocol() : header_size_(sizeof(Header)), name_(name){};

  // Template Method pattern
  RawProto Parse(Stream& packet, std::streamsize& packet_size) {
    Header header = GetHeader(packet, packet_size);
    Transform(header);
    Operation(header);
    return GetNextProto(header);
  }
};

template <class Header, char const* name>
Header Protocol<Header, name>::GetHeader(Stream& packet,
                                         std::streamsize& packet_size) {
  Header header{};

  if (packet_size < header_size_)
    throw NotEnoughData(name_, header_size_, packet_size);

  packet.read(reinterpret_cast<char*>(&header), header_size_);

  if (packet.eof()) {
    packet_size = 0;
    throw EoF(name_, header_size_, packet.gcount());
  }

  packet_size -= header_size_;

  return header;
}

void HexdumpBytes(Stream& packet, std::streamsize n);

void TrimBytes(Stream& packet, std::streamsize n);

RawProto HandleParser(BaseParser& p, Stream& packet,
                      std::streamsize& packet_size, RawProto curr_proto);
}  // namespace packet_parse
