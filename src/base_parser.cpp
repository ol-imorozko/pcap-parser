#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>

#include "include/base_parser.h"

namespace packet_parse {

void Hexdump(const uint8_t* data, size_t size) {
  int kBytesPerLine = 16;

  for (size_t i = 0; i < size; i++) {

    if (i % kBytesPerLine == 0)
      std::cout << std::hex << std::setfill('0') << std::setw(8) << i << ": ";

    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<int>(data[i]) << " ";
    if ((i + 1) % kBytesPerLine == 0 || i + 1 == size) {
      size_t j;

      for (j = 0; j < kBytesPerLine - (i % kBytesPerLine) - 1; j++)
        std::cout << "   ";

      if ((i + 1) % kBytesPerLine != 0)
        std::cout << " ";

      for (j = i - (i % kBytesPerLine); j <= i; j++) {
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

void HexdumpBytes(std::ifstream& file, std::streamsize n) {
  auto packet_data = std::make_unique<uint8_t[]>(n);
  file.read(reinterpret_cast<char*>(packet_data.get()), n);
  Hexdump(packet_data.get(), file.gcount());
}

void TrimBytes(std::ifstream& file, std::streamsize n) {
  if (file)
    file.seekg(static_cast<long>(n), std::ios::cur);
}

RawProto HandleParser(const BaseParser& p, std::ifstream& file,
                      std::streamsize& packet_size, RawProto curr_proto) {
  try {
    RawProto next_proto = p.Parse(file, packet_size, curr_proto);
    return next_proto;
  } catch (const std::exception& e) {
    std::cerr << e.what() << "\nData left: \n";

    if (packet_size == 0)
      std::cerr << "No data left\n";
    else {
      HexdumpBytes(file, packet_size);
      packet_size = 0;
    }

    return 0;
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
