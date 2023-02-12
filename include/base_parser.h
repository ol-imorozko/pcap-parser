#pragma once
#include <exception>
#include <fstream>
#include <ios>
#include <limits>
#include <memory>
#include <utility>

namespace packet_parse {

using Stream = std::basic_istream<char>;

// Different protocols could use different fixed num unsigned
// data types, so in order to create a unified interface it
// is better to cast such types to uint64_t.
using RawProto = uint64_t;
constexpr RawProto kNoProtoNeeded = std::numeric_limits<uint64_t>::max();

// Sometimes it is helpful to pass some data from the bottom level parser
// to the top one. For example, the header for some protocol could contain
// the size of a following data. In that case we should pass that size to
// the next layer parser. We can use "ServiceData" structure for that.
//
// Usually this data will contain identifier of the next protocol,
// so it's a default field;
struct ServiceData {
  RawProto proto = kNoProtoNeeded;

  ServiceData() = default;
  explicit ServiceData(RawProto proto) : proto(proto){};
  explicit ServiceData(uint32_t proto) : proto(static_cast<RawProto>(proto)){};
};
using ServiceDataPtr = std::unique_ptr<ServiceData>;

class UnknownProto : public std::exception {
 private:
  std::string msg;

 public:
  explicit UnknownProto(RawProto proto);

  const char* what() const noexcept override { return msg.c_str(); };
};

class UnsupportedL4Payload : public std::exception {
 private:
  std::string msg;

 public:
  explicit UnsupportedL4Payload(const std::string& protocol_name);

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
  virtual ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                               ServiceDataPtr data) const = 0;
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
    return kNoProtoNeeded;
  };

  virtual ServiceDataPtr Operation([[maybe_unused]] const Header& header,
                                   ServiceDataPtr data) {
    return data;
  };

 public:
  Protocol() : header_size_(sizeof(Header)), name_(name){};

  // Template Method pattern
  ServiceDataPtr Parse(Stream& packet, std::streamsize& packet_size,
                       ServiceDataPtr data) {
    Header header = GetHeader(packet, packet_size);
    Transform(header);
    ServiceDataPtr new_data = Operation(header, std::move(data));
    new_data->proto = GetNextProto(header);
    return new_data;
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

// This function calls Parse() method of a BaseParser and handles exceptions, if any.
// Protocol parsers will get ServiceData, use it (if necessary), and then
// they could change it for the next parser.
ServiceDataPtr HandleParser(const BaseParser& p, Stream& packet,
                            std::streamsize& packet_size, ServiceDataPtr data);
}  // namespace packet_parse
