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

void hexdump(const uint8_t* data, size_t size);

void ParsePcapPackets(PcapFileHeader& file_header, std::ifstream& file) {
  file_header.Print();

  // Read PCAP packets
  while (!file.eof()) {
    // Read raw PCAP packet header
    auto raw_packet_header = ReadRawHeader<RawPcapPacketHeader>(file);

    // Check if it's the end of file
    if (file.eof())
      break;

    // Get normal PCAP packet header
    PcapPacketHeader packet_header(raw_packet_header, file_header);

    packet_header.Print();

    // Read packet data
    // TODO: fix this
    unsigned int packet_length = packet_header.GetCapturedPacketLength();
    uint8_t packet_data[packet_length];
    memset(packet_data, 0, packet_length);
    file.read(reinterpret_cast<char*>(packet_data), packet_length);

    // Do something with the packet data
    // temporarily dumping it
    packet_header.PrintTimeStamp();
    /* hexdump(packet_data, packet_length); */
  }
}

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
  auto raw_file_header = ReadRawHeader<RawPcapFileHeader>(file);

  // Get normal PCAP file header
  try {
    PcapFileHeader file_header(raw_file_header);
    ParsePcapPackets(file_header, file);
  } catch (const std::exception& e) {
    std::cerr << argv[1] << "is not a PCAP file" << std::endl;
  }

  // Close the file
  file.close();

  return 0;
}

// Temporary
#include <iomanip>

constexpr int BYTES_PER_LINE = 16;

void hexdump(const uint8_t* data, size_t size) {
  size_t i;
  for (i = 0; i < size; i++) {
    if (i % BYTES_PER_LINE == 0) {
      std::cout << std::hex << std::setfill('0') << std::setw(8) << i << ": ";
    }
    std::cout << std::hex << std::setfill('0') << std::setw(2) << int(data[i])
              << " ";
    if ((i + 1) % BYTES_PER_LINE == 0 || i + 1 == size) {
      size_t j;
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
