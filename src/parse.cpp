#include <cstring>
#include <fstream>
#include <iostream>

#include "include/pcap_headers.h"

template <class T>
T ReadRawHeader(std::ifstream& file) {
  T raw_header{};
  file.read(reinterpret_cast<char*>(&raw_header), sizeof(T));
  return raw_header;
}

std::string TimeFormatToString(TimeFormat& tf) {
  return tf == TimeFormat::kUSec ? "Microseconds" : "Nanoseconds";
}

void hexdump(const uint8_t* data, int size);

int main(int argc, char* argv[]) {
  // Check if the file name is provided
  if (argc != 2) {
    std::cout << "Usage: pcap_parser <file_name>" << std::endl;
    return 0;
  }

  // Open the file
  std::ifstream file(argv[1], std::ios::in | std::ios::binary);
  if (!file) {
    std::cout << "Failed to open the file" << std::endl;
    return 0;
  }

  // Read raw PCAP file header
  auto file_header = ReadRawHeader<PcapFileHeader>(file);

  // Check if it's a PCAP file
  if (!file_header.FileValid()) {
    std::cout << "Not a PCAP file" << std::endl;
    return 0;
  }

  //Create transformer object to transform headers according to endianness
  Transformer transformer(file_header.get_endianess());

  // Transfrorm raw PCAP file header and print it
  file_header.Transform(transformer);
  file_header.Print();

  TimeFormat time_format = file_header.get_timeformat();
  std::cout << TimeFormatToString(time_format) << " timestamp" << std::endl;

  // Read PCAP packets
  while (!file.eof()) {
    // Read raw PCAP packet header
    auto packet_header = ReadRawHeader<PcapPacketHeader>(file);

    // Check if it's the end of file
    if (file.eof())
      break;

    // Transfrorm raw PCAP packet header and print it
    packet_header.Transform(transformer);
    packet_header.Print();

    // Read packet data
    uint8_t packet_data[packet_header.incl_len];
    memset(packet_data, 0, packet_header.incl_len);
    file.read(reinterpret_cast<char*>(packet_data), packet_header.incl_len);

    // Do something with the packet data
    // temporarily dumping it
    packet_header.PrintTimeStamp(time_format);
    hexdump(packet_data, packet_header.incl_len);
  }

  // Close the file
  file.close();

  return 0;
}

// Temporary
#include <iomanip>

constexpr int BYTES_PER_LINE = 16;

void hexdump(const uint8_t* data, int size) {
  int i;
  for (i = 0; i < size; i++) {
    if (i % BYTES_PER_LINE == 0) {
      std::cout << std::hex << std::setfill('0') << std::setw(8) << i << ": ";
    }
    std::cout << std::hex << std::setfill('0') << std::setw(2) << int(data[i])
              << " ";
    if ((i + 1) % BYTES_PER_LINE == 0 || i + 1 == size) {
      int j;
      for (j = 0; j < BYTES_PER_LINE - (i % BYTES_PER_LINE) - 1; j++) {
        std::cout << "   ";
      }
      if ((i + 1) % BYTES_PER_LINE != 0) {
        std::cout << " ";
      }
      for (j = i - (i % BYTES_PER_LINE); j <= i; j++) {
        if (data[j] >= 32 && data[j] <= 126) {
          std::cout << char(data[j]);
        } else {
          std::cout << ".";
        }
      }
      std::cout << std::dec << std::endl;
    }
  }
}
