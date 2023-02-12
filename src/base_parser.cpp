#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>

#include "include/base_parser.h"

namespace packet_parse {

void Hexdump(const uint8_t* data, size_t size) {
  const int bytes_per_line = 16;

  for (size_t i = 0; i < size; i++) {

    if (i % bytes_per_line == 0)
      std::cout << std::hex << std::setfill('0') << std::setw(8) << i << ": ";

    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<int>(data[i]) << " ";
    if ((i + 1) % bytes_per_line == 0 || i + 1 == size) {
      size_t j;

      for (j = 0; j < bytes_per_line - (i % bytes_per_line) - 1; j++)
        std::cout << "   ";

      if ((i + 1) % bytes_per_line != 0)
        std::cout << " ";

      for (j = i - (i % bytes_per_line); j <= i; j++) {
        if (data[j] >= 32 && data[j] <= 126)
          std::cout << static_cast<char>(data[j]);
        else
          std::cout << ".";
      }
      std::cout << std::dec << '\n';
    }
  }
  std::cout << std::dec;
}

void HexdumpBytes(Stream& packet, std::streamsize n) {
  auto packet_data = std::make_unique<uint8_t[]>(n);
  packet.read(reinterpret_cast<char*>(packet_data.get()), n);
  Hexdump(packet_data.get(), packet.gcount());
}

void TrimBytes(Stream& packet, std::streamsize n) {
  if (packet)
    packet.seekg(static_cast<long>(n), std::ios::cur);
}

ServiceDataPtr HandleParser(const BaseParser& p, Stream& packet,
                            std::streamsize& packet_size, ServiceDataPtr data) {
  try {
    return p.Parse(packet, packet_size, std::move(data));
  } catch (const std::exception& e) {
    std::cerr << e.what() << "\nData left: \n";

    if (packet_size == 0)
      std::cerr << "No data left\n";
    else {
      HexdumpBytes(packet, packet_size);
      packet_size = 0;
    }

    return std::make_unique<ServiceData>();
  }
}

UnknownProto::UnknownProto(RawProto proto) {
  std::ostringstream oss;
  oss << "Unknown protocol 0x" << std::hex << proto << std::dec;

  msg = oss.str();
}

NotEnoughData::NotEnoughData(const std::string& protocol_name,
                             size_t protocol_header_size,
                             size_t obtained_size) {
  std::ostringstream oss;
  oss << protocol_name << " parser expects to get " << protocol_header_size
      << " bytes, but got only " << obtained_size;

  msg = oss.str();
}

EoF::EoF(const std::string& protocol_name, size_t protocol_header_size,
         size_t obtained_size) {
  std::ostringstream oss;
  oss << protocol_name << " parser attempted to read " << protocol_header_size
      << " bytes, but got only " << obtained_size << " and the file ended";

  msg = oss.str();
}

}  // namespace packet_parse
