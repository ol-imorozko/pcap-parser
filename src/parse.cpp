#include <cstring>
#include <fstream>
#include <iostream>

#include "include/pcap_headers.h"
#include "include/pcap_headers_helper.h"

template <class T>
T ReadRawHeader(std::ifstream& file) {
  T raw_header{};
  file.read(reinterpret_cast<char*>(&raw_header), sizeof(T));
  return raw_header;
}

void hexdump(const uint8_t* data, int size);

int main(int argc, char* argv[]) {
  // Check if the file name is provided
  if (argc < 2) {
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
  auto raw_file_header = ReadRawHeader<PcapFileHeader>(file);

  PcapHeadersHelper headers_helper(raw_file_header.magic_number);

  // Check if it's a PCAP file
  if (!headers_helper.FileValid()) {
    std::cout << "Not a PCAP file" << std::endl;
    return 0;
  }

  // Transfrorm raw PCAP file header according to endianness
  PcapFileHeader file_header =
      headers_helper.TransfrormRawFileHeader(raw_file_header);
  PcapHeadersHelper::PrintPcapFileHeader(file_header);

  // Read PCAP packets
  while (!file.eof()) {
    // Read PCAP packet header
    auto raw_packet_header = ReadRawHeader<PcapPacketHeader>(file);

    // Check if it's the end of file
    if (file.eof())
      break;

    // Transfrorm raw PCAP packet header according to endianness
    PcapPacketHeader packet_header =
        headers_helper.TransfrormRawPacketHeader(raw_packet_header);
    PcapHeadersHelper::PrintPcapPacketHeader(packet_header);

    // Read packet data
    uint8_t packet_data[packet_header.incl_len];
    memset(packet_data, 0, packet_header.incl_len);
    file.read(reinterpret_cast<char*>(packet_data), packet_header.incl_len);

    // Do something with the packet data
    // temporarily dumping it
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
      std::cout << std::endl;
    }
  }
}
